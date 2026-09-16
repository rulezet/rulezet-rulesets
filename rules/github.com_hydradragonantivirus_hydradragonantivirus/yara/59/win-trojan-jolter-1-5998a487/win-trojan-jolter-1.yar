rule Win_Trojan_Jolter_1
{
strings:
	$a0 = { 8c16910989268f098ed3bc790bfb833e0301007411a18109be4a01b95f09c6060b0130e8c1ff }


condition:
	$a0
}