rule Win_Trojan_BadGuy_2
{
strings:
	$a0 = { 01b14f902e8a1780f24390b402cd21 }


condition:
	$a0
}