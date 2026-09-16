import "pe"
rule DotNET_RunPE_Obfuscated
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:	
		$a0 = "conff" wide ascii nocase
		$a1 = "isSandboxie" wide ascii nocase
		$a2 = "isWPE" wide ascii nocase
		$a3 = "Anti" wide ascii nocase
		$a4 = "RunPE" wide ascii nocase
		$a5 = "isFiddler" wide ascii nocase
		$a6 = "DeCrypt" wide ascii nocase
		$a7 = "CreateProcess" wide ascii nocase
		$a8 = "SbieDll" wide ascii nocase
		$a9 = "InjectPE" wide ascii nocase
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 5 of ($a*)
}