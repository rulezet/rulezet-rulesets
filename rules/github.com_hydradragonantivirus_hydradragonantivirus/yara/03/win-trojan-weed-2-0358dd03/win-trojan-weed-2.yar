rule Win_Trojan_Weed_2
{
strings:
	$a0 = { 9a0000aa005589e5e8c3febf2d080e576a23bf6e021e579a88008c00e8b6fa08c0b00075014050bf8c021e57e8eefa08 }


condition:
	$a0
}