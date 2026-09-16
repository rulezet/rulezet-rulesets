rule Win_Trojan_Int_FF_1
{
strings:
	$a0 = { cdffc7065704eb018306470402c70643045a4db8004233d233c9cdffba4304b440b91c00cdff }


condition:
	$a0
}