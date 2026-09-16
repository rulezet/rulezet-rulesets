rule Win_Trojan_W_238
{
strings:
	$a0 = { ac32c1aae2fac3fc33c9498bd133c033dbac32c18acd8aea8ad6b6 }


condition:
	$a0
}