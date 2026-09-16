rule Win_Trojan_Jerusalem_39
{
strings:
	$a0 = { 80fc2b750a80facc7505b8ff339dcf3d004b747080fc3d }


condition:
	$a0
}