rule Win_Trojan_Vriest_3
{
strings:
	$a0 = { b489cd213d23017432b82135cd218c06 }


condition:
	$a0
}