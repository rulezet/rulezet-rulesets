rule Win_Trojan_Jacov_11
{
strings:
	$a0 = { 03cf8db617018bfeb9ff00ad7304abe2fac335795673f7 }


condition:
	$a0
}