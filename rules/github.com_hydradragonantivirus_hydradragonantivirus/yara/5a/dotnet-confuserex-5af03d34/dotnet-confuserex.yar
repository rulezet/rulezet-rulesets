import "pe"
rule DotNET_ConfuserEx : Ki
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:	
		$a0 = { 43 6F 6E 66 75 73 65 72 45 78 20 76 }
		$a1 = { 43 6F 6E 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 00 41 74 74 72 69 62 75 74 65 }
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 1 of ($a*)
}