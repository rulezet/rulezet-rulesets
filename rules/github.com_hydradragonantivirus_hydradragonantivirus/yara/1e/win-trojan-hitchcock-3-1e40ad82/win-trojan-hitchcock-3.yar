rule Win_Trojan_Hitchcock_3
{
strings:
	$a0 = { 02b82125cd21c70600029411c706 }


condition:
	$a0
}