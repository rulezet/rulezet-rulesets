rule Win_Trojan_BW_5
{
strings:
	$a0 = { 8bf5b90901f3a533c08ed8be8400bfa700a5a5c744fc85008c44fe071f8db603 }


condition:
	$a0
}