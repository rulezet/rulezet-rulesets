rule Win_Trojan_E_11
{
strings:
	$a0 = { 7c01721f26813feb7e751826c7074d5a575150b9150133c089df81c78000f3aa58595fcf2e }


condition:
	$a0
}