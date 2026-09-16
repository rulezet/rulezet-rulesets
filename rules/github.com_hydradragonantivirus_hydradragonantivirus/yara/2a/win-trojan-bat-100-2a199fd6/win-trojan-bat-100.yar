rule Win_Trojan_BAT_100
{
strings:
	$a0 = { cd21e9e0002a2e424154 }

	$a1 = { 40434f505920253020272e4558453e4e554c0d0a40270d0a4044454c20272e455845 }


condition:
	$a0 and $a1
}