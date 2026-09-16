rule Win_Trojan_SillyRE_4
{
strings:
	$a0 = { 164b0087066a00a35000b440ba0000b90002cd21b8004233c999cd21b440ba5a00b91800cd21c3 }


condition:
	$a0
}