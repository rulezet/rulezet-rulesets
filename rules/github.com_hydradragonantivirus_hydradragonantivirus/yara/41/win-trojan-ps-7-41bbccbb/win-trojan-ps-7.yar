rule Win_Trojan_PS_7
{
strings:
	$a0 = { e800005d81ed080190e8 }

	$a1 = { b9be028db6????8bfeac2e32a6????aae2f7c3 }


condition:
	$a0 and $a1
}