rule Win_Trojan_R_79
{
strings:
	$a0 = { e81400eb24e80f00b440b961018bd5cd21e80300c3 }


condition:
	$a0
}