import "pe"
rule DotNET_ConfuserAvalon : Avalon
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:	
		$a0 = { 43 6F 6E 66 75 73 65 64 42 79 41 76 61 6C 6F 6E 50 72 6F 74 65 63 74 6F 72 }
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 1 of ($a*)
}