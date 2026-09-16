rule Win_Trojan_V_106
{
strings:
	$a0 = { c8a3a704a3ab04a3af04c606630400e8cc02e81d037303e9ad002e8e062c00fc33ff32c0b9ff00f2ae26803d0075f3 }


condition:
	$a0
}