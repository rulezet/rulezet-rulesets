rule Win_Trojan_Jacov_12
{
strings:
	$a0 = { 8db617018bfeb90001ad7304abe2fac3352e4273f7 }


condition:
	$a0
}