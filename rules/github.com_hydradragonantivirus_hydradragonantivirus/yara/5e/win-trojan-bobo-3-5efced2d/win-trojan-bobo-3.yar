rule Win_Trojan_Bobo_3
{
strings:
	$a0 = { 8bf5a4a4a4b8ab4bcd213db0b075170e1f0e0733c033db33c933d233ed33ffbe00015633f6 }


condition:
	$a0
}