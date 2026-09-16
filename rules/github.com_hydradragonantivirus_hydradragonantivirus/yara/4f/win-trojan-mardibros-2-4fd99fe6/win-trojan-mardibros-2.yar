rule Win_Trojan_MardiBros_2
{
strings:
	$a0 = { 8cc88ed88ed0bc00f0fbe82700fa31c08ed8a113042d0700 }


condition:
	$a0
}