rule Win_Trojan_Aiwedr_1
{
strings:
	$a0 = { 6700f8b8addecd21724be874020e0732c0b91c00bfa602 }


condition:
	$a0
}