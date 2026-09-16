rule Win_Trojan_TPVO_6
{
strings:
	$a0 = { 75faadad8bd6e85f037509928ec3bb8000e88e03b80102bbea0d0e07b90100ba8000cd13cb }


condition:
	$a0
}