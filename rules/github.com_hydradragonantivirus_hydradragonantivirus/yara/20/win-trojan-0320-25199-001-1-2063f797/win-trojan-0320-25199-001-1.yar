rule Win_Trojan__0320_25199_001_1
{
strings:
	$a0 = { 13b80042e83b00b440ba0001b9e30090cd217200b43ecd21beac01bf3eff57b9190090fcf3a4 }


condition:
	$a0
}