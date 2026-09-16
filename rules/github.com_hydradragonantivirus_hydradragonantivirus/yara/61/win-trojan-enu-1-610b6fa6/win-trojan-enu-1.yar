rule Win_Trojan_Enu_1
{
strings:
	$a0 = { f9ffcd21b440b9eb008d960401cd21b800422bc999cd21c686ef01e98b8e0d0283e90a898ef001 }


condition:
	$a0
}