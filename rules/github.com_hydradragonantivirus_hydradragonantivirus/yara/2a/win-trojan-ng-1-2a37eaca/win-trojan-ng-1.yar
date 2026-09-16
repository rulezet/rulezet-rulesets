rule Win_Trojan_Ng_1
{
strings:
	$a0 = { 33c933d22e8b1e6e01cd21c3b440ba0001b9b702ebee53bb03012e8037234381fb690175f5 }


condition:
	$a0
}