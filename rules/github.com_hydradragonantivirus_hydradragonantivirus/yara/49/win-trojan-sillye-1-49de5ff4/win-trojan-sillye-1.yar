rule Win_Trojan_SillyE_1
{
strings:
	$a0 = { 258bd381c2b302cd21b801258bd381c2c602cd21b401b280cd138bf38bfb81c68c0281c79002 }


condition:
	$a0
}