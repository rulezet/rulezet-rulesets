rule Win_Trojan_Evolution_1
{
strings:
	$a0 = { 0e1f6824005f8d0eb1020e07668b0483c60466351e4fad2a66890583c704e2 }


condition:
	$a0
}