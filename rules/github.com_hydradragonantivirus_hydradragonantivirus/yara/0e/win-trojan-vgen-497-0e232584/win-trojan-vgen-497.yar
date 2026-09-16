rule Win_Trojan_VGEN_497
{
strings:
	$a0 = { 8bd0b800427305fec0fec09933c9cd21c3b80143cd21c332c0cf }


condition:
	$a0
}