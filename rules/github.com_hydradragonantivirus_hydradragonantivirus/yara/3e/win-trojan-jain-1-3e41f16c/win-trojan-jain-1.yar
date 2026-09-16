rule Win_Trojan_Jain_1
{
strings:
	$a0 = { 02ebf32e8b3e7005b041ae7404b400eb02b4ffc3b80102bb0008cd13c30656b413cd2f1e53cd2f }


condition:
	$a0
}