rule Win_Trojan_Winbomb_1
{
strings:
	$a0 = { 28693d313b693e303b692b2b297b6f70656e28226469652e68746d222c226e6577222b6929 }


condition:
	$a0
}