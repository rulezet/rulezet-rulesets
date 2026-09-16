rule Win_Trojan_Experiments_1
{
strings:
	$a0 = { 5d83ed03eb05feffb003cfb8f302060e1fb42fcd210653b413cd2f2e8996f3022e8c9ef502b413cd2f1e33c050 }


condition:
	$a0
}