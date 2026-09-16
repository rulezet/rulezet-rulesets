rule Win_Trojan_Trasher_2
{
strings:
	$a0 = { be0301b972008134????4646e2f8c3 }


condition:
	$a0
}