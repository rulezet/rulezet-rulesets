rule Win_Trojan_Norway_2
{
strings:
	$a0 = { 36030181c60501893600018bee8d761e90b98302803428802c3546e2f7 }


condition:
	$a0
}