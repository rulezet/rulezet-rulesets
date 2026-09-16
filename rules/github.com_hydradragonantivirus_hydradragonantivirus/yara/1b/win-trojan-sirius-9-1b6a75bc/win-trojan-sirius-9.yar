rule Win_Trojan_Sirius_9
{
strings:
	$a0 = { e80200eb108a966301b94a018bfeac32c2aae2fac3 }


condition:
	$a0
}