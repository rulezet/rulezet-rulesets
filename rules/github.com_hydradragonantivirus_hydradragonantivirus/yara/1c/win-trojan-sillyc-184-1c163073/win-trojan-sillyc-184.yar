rule Win_Trojan_SillyC_184
{
strings:
	$a0 = { e80200eb108a966101b948018bfeac32c2aae2fac3 }


condition:
	$a0
}