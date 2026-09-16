import "pe"
rule DotNET_PERun_Rev_Obfuscated
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:	
		$a0 = "daoL" wide ascii nocase
		$a1 = "epyTteG" wide ascii nocase
		$a2 = "dohteMteG" wide ascii nocase
		$a3 = "ekovnI" wide ascii nocase
		$a4 = "tnioPyrtnE" wide ascii nocase
		$a5 = "hex2Byt" wide ascii nocase
		$a6 = "Reverse" wide ascii nocase
		$a7 = "PE\x00Run" wide ascii nocase
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 5 of ($a*)
}