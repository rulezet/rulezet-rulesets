rule Win_Trojan_Agent_36752
{
strings:
	$a0 = { 4d52472e646c6c0073696d756c6174696f6e2e6c6f6700534f4654574152455c }


condition:
	$a0
}