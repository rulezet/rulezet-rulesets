rule Win_Trojan_Jacov_3
{
strings:
	$a0 = { 8db617018bfeb9e600ad7304abe2fac335734173f7 }


condition:
	$a0
}