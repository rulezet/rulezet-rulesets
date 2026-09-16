rule Win_Trojan_Monster_14
{
strings:
	$a0 = { b9eb01bede2cfc300446e2fb25cdcd934e23ce0b89c13326cd0b89c1cd2547cc47492fcc6fcdcc46492ecc6ecccc }


condition:
	$a0
}