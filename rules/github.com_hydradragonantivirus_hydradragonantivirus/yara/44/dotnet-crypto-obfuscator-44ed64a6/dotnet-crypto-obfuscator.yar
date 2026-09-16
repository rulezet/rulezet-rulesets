import "pe"
rule DotNET_Crypto_Obfuscator : LogicNP Software
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:	
		$a0 = { 7E ?? ?? ?? ?? 02 91 20 3F FF FF FF 5F 1F 18 62 0A 06 7E ?? ?? ?? ?? 02 17 58 91 1F 10 62 60 0A 06 7E }
		$a1 = { 20 ?? ?? 00 02 20 ?? ?? 00 0A 20 FF FF FF 00 28 ?? ?? ?? ?? 2A }
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 1 of ($a*)
}