import "pe"
rule DotNET_SmartAssembly : RedGate
{
	meta:
		author="_pusher_"
		date="2016-07"
	strings:	
		$a0 = { 50 6F 77 65 72 65 64 20 62 79 20 53 6D 61 72 74 41 73 73 65 6D 62 6C 79 20 }
		$a1 = { 50 6F 77 65 72 65 64 20 62 79 20 7B 73 6D 61 72 74 61 73 73 65 6D 62 6C 79 7D }
	condition:
		(pe.imports ("mscoree.dll","_CorExeMain") or pe.imports ("mscoree.dll","_CorDllMain")) and 1 of ($a*)
}