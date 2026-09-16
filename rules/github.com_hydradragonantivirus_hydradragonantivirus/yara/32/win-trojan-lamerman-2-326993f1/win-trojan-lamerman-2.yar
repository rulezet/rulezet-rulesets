rule Win_Trojan_Lamerman_2
{
strings:
	$a0 = { 2ec70600019090b80102b90100ba8000bb0003cd13725b81c3be018bf3b90400803c80740783c610e2f6 }


condition:
	$a0
}