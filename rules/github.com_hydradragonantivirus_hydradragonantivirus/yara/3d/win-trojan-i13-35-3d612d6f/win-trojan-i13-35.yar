rule Win_Trojan_I13_35
{
strings:
	$a0 = { 4897dabfa69c65cd57bd258d572c523da69c8ecd258dd4b10097cf572c523da69c79cd258dd4b100 }


condition:
	$a0
}