rule Win_Trojan_NV_1
{
strings:
	$a0 = { fc8cda83c2102e0116030033c08e }


condition:
	$a0
}