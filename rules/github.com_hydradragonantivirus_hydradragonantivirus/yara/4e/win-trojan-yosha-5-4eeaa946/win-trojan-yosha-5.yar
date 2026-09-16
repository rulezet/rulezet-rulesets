rule Win_Trojan_Yosha_5
{
strings:
	$a0 = { 8bec8b6efafb4d4d061efcb84344cd213d3e3a75311f078cc00510002e01864200cc2e03864400fa8ed02e8ba646 }


condition:
	$a0
}