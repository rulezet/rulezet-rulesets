rule Win_Trojan_Zub_1
{
strings:
	$a0 = { 568bf4368944fe83ec025b81eb71568bebe900008db65f018bfe0e0e1f07b9a40090ad2e8b96 }


condition:
	$a0
}