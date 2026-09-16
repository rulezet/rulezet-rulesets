rule Win_Trojan_Gen_231
{
strings:
	$a0 = { e2a8e4a8aaa0e2aee0a020a1a8e2a020aeafa8e1a0e2a5abef206e3338243535362e2082aea7 }


condition:
	$a0
}