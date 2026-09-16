rule Win_Trojan_SillyRCE_8
{
strings:
	$a0 = { 6403c70660031002ff065403b44099b9d001e83000b8004233c9cd21b440ba5003b118e81f00 }


condition:
	$a0
}