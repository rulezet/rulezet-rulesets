rule ms_vc7_dll3
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.0 DLL Method 3"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C }
	condition:
		$a0
}