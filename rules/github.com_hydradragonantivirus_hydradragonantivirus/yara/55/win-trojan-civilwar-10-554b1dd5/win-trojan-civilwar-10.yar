rule Win_Trojan_CivilWar_10
{
strings:
	$a0 = { 0242e83b002d03008986f101b80042e82e00e84300b80242e82500b440b9f0008d960301cd }


condition:
	$a0
}