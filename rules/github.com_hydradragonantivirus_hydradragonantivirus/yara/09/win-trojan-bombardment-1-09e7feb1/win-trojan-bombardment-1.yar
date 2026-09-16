rule Win_Trojan_Bombardment_1
{
strings:
	$a0 = { 9a000082029a000016029a0000e50089e5c606061400bff30c0e57bff3131e57b80800509a87028202b8a80c8cca5250 }


condition:
	$a0
}