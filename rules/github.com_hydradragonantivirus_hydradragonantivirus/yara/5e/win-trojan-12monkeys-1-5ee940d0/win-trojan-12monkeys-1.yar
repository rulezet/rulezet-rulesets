rule Win_Trojan_12Monkeys_1
{
strings:
	$a0 = { 0501e82200eb2f90b42ccd2180fa0074f788963801e80f00b440b9c4018d960001cd21e80100 }


condition:
	$a0
}