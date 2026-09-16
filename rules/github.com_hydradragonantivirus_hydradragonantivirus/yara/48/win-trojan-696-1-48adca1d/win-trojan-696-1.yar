rule Win_Trojan_696_1
{
strings:
	$a0 = { 450175f683c7048bd7b8023dcd21 }


condition:
	$a0
}