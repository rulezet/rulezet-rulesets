rule Win_Trojan_Ol_1
{
strings:
	$a0 = { 050aea01b0d9c925394b482a881ad3010a1b037106ef2c1a02f8 }


condition:
	$a0
}