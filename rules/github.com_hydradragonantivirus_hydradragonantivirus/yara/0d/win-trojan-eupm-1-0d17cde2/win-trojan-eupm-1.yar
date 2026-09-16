rule Win_Trojan_EUPM_1
{
strings:
	$a0 = { 01008cc88ed8b9a006bf03002ea000002e000547e2 }


condition:
	$a0
}