rule Win_Trojan_Jacov_4
{
strings:
	$a0 = { 8db617018bfeb9f100ad7304abe2fac335681773f7 }


condition:
	$a0
}