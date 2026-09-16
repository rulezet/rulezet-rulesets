rule Win_Trojan_Yankee_7
{
strings:
	$a0 = { 44a78bfeb950072e8abc200802fee8b600071f58c3 }


condition:
	$a0
}