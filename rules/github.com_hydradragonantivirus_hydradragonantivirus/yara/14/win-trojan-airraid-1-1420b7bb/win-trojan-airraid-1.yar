rule Win_Trojan_AirRaid_1
{
strings:
	$a0 = { 7261cd210ac0754c5633ff1e8cc8488ed8bb1a00c6054d }


condition:
	$a0
}