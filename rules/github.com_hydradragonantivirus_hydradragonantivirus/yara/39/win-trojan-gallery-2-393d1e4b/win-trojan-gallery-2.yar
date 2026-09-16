rule Win_Trojan_Gallery_2
{
strings:
	$a0 = { 83ed0390b9dd01be1100e86f02ab1323de322f176010fad413abed41de322e41ed359854ed9a957f116610faa11335 }


condition:
	$a0
}