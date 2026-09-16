rule Win_Trojan_IRC_Script_18
{
strings:
	$a0 = { 7b20436d44426f542024312d207d }

	$a1 = { 29207b2072657475726e2052454745444954207d }


condition:
	$a0 and $a1
}