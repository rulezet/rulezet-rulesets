rule Win_Trojan_Monster_25
{
strings:
	$a0 = { 02bede2cfc300446e2fb26e896ed8082839e99889fed9091cde7e3e7cde7e38e8280cd3699ce2400e6cddfcf }


condition:
	$a0
}