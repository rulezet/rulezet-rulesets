rule Win_Trojan_Pester_1
{
strings:
	$a0 = { 5dc3558bec1eb4408b5e048b4e0ac55606cd211f72098b5e0c890733c0eb0450e8c9015dc3c355 }


condition:
	$a0
}