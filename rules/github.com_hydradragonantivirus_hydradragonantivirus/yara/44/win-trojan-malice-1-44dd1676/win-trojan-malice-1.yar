rule Win_Trojan_Malice_1
{
strings:
	$a0 = { 21e968ff8d960502b43bcd217203e949ffb42ccd21b419cd21fec032f6b901008d9e3302cd26eb }


condition:
	$a0
}