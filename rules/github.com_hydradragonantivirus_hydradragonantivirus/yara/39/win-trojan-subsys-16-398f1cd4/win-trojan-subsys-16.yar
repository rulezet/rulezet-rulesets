rule Win_Trojan_Subsys_16
{
strings:
	$a0 = { c359dc0ce5dc5b6e08fd33db995893d26908fc047671de0ad8974688d9352b3266552e04d73957bf1b4119edf249fcf8 }


condition:
	$a0
}