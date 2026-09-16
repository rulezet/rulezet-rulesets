rule Win_Trojan_Gen_138
{
strings:
	$a0 = { 8a0e0900bb36008a0732c1fec188074381fb34037ef1 }


condition:
	$a0
}