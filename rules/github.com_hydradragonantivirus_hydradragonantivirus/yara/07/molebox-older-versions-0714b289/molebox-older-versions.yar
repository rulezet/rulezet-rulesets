import "pe"
rule MoleBox_older_versions : Teggo Software Ltd
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$c0 = { E8 ?? ?? FF FF 58 E8 75 03 00 00 58 89 44 24 1C 61 FF E0 CC }
		$c1 = { E8 ?? ?? FF FF 58 E8 55 07 00 00 58 89 44 24 ?? 61 58 58 FF D0 E8 }
		$c9 = { E8 ?? ?? FF FF 58 E8 55 07 00 00 58 89 44 24 ?? 61 58 FF D0 E8 }
		$c8 = { E8 ?? ?? ?? ?? 6A 00 54 6A 00 E8 ?? ?? ?? ?? 87 04 24 E8 ?? ?? ?? ?? 5F 5E 5E 89 EC 5D FF E0 }
		$c2 = { 27 48 45 52 45 49 53 42 4F 4F 54 43 4F 44 45 27 }
		$c3 = { 0D 4D 4F 4C 45 42 4F 58 32 }
	condition:
		pe.imports ("kernel32.dll","GetProcAddress") and
		pe.imports ("kernel32.dll","GetModuleHandleA") and
		pe.imports ("kernel32.dll","MultiByteToWideChar") and
		pe.imports ("kernel32.dll","RaiseException") and
		pe.imports ("kernel32.dll","LocalAlloc") and
		pe.imports ("kernel32.dll","LocalFree") and
		($c0 or $c1 or $c9 ) and ($c2 or $c3) or ($c8)
}