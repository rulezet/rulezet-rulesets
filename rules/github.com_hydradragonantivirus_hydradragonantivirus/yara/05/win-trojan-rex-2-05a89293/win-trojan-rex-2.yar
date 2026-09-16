rule Win_Trojan_Rex_2
{
strings:
	$a0 = { 8a1c2e021e1601881c4681fe530375f0e9c101 }


condition:
	$a0
}