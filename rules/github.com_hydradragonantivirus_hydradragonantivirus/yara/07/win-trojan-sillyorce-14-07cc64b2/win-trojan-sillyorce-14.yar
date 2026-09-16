rule Win_Trojan_SillyORCE_14
{
strings:
	$a0 = { 2135cd2106583d60007425891e5401a35601b860008ec00e1f33ffb158f3a48ed8ba3200b82125cd21ba5300b0ffcd }


condition:
	$a0
}