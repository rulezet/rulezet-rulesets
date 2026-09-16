rule Win_Trojan_MH_1
{
strings:
	$a0 = { be3201662e01026603c383c604662e01022ec6863201be83c60481fedb0672e3 }


condition:
	$a0
}