rule Win_Trojan_Duke_9
{
strings:
	$a0 = { 96f402eb0059eb00cd2180c1d980e9d97213b05ab002e83d00b440b9c501908d960501cd21 }


condition:
	$a0
}