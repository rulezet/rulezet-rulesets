rule Win_Trojan_Discom_3
{
strings:
	$a0 = { bf0001be000803f72e8b4d11cd21 }


condition:
	$a0
}