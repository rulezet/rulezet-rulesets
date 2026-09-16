rule Win_Trojan_Nutmeg_2
{
strings:
	$a0 = { cc0003c28bd8053e018edb8ec033f633ffb90800f3a54b484a79ee8ed88ec3be4700ad8be8b210 }


condition:
	$a0
}