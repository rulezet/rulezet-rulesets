rule Win_Trojan_Gullich_1
{
strings:
	$a0 = { c08ed0bc007bfb52561ebb677cb94701368037e743e2f9 }


condition:
	$a0
}