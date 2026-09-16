rule Win_Trojan_Roet_1
{
strings:
	$a0 = { cd21ebc3742f8cc0ebc4812e12008000ebc88bf5b9 }


condition:
	$a0
}