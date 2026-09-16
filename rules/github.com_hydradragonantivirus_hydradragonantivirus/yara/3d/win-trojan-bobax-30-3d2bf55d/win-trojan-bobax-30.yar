rule Win_Trojan_Bobax_30
{
strings:
	$a0 = { e82200000033ca8a5b3822ace798fe8a0eb8042711db8a23e95b4c1addea498ae8000000007e00 }


condition:
	$a0
}