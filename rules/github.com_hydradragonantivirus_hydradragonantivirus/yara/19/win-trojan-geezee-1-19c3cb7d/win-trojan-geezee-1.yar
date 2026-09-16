rule Win_Trojan_GeeZee_1
{
strings:
	$a0 = { cd2180fcf074d2b853008ec0b9d001fcf3a4ea5a015300 }


condition:
	$a0
}