import "pe"
rule DotNET_DotFuscator : PreEmptive Solutions
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:	
		$a0 = { 00 44 6F 74 66 75 73 63 61 74 6F 72 41 74 74 72 69 62 75 74 65 00 }
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 1 of ($a*)
}