rule Win_Trojan_DSME_6
{
strings:
	$a0 = { 8cc88ed8b45bcd2193be48018bdbb907008bd68cc88ed8b440cd218bdbb43ecd2161e2d1ba }


condition:
	$a0
}