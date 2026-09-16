rule Win_Trojan_Pinky_2
{
strings:
	$a0 = { 01b9a503be0c018bfefcac32c4aae2fac30e070e1fe8e5ffe92aff9090 }


condition:
	$a0
}