rule Win_Trojan_V_14
{
strings:
	$a0 = { be00014603348bfe33c9b87a025033 }


condition:
	$a0
}