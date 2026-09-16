rule Win_Trojan_Jacov_5
{
strings:
	$a0 = { 8db617018bfeb9f100ad7304abe2fac335243273f7 }


condition:
	$a0
}