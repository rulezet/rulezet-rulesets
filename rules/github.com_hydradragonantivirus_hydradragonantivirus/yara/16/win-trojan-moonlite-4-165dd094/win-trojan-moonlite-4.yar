rule Win_Trojan_Moonlite_4
{
strings:
	$a0 = { 1700eb2790e811008d960301b9d101b440cd21e80300c3 }


condition:
	$a0
}