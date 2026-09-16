rule Win_Trojan_Jain_3
{
strings:
	$a0 = { 02ebf32e8b3e2205b041ae7404b400eb02b4ffc3b80102bb0008cd13c30656b40dcd2f1e53cd2f }


condition:
	$a0
}