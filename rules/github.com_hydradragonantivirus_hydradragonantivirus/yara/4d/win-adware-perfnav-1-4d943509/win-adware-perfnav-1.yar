rule Win_Adware_Perfnav_1
{
strings:
	$a0 = { ff150c0201108945ec8d45d050c745f0060000008975f4c745f8bc0201108975fcff1510020110 }


condition:
	$a0
}