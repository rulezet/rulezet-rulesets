rule Win_Trojan_Pebble_2
{
strings:
	$a0 = { 0e0e01b80103ba8000cd137301cbbebe04bfbe02b92100fcf3a5b80103bb0001b90100cd13cb }


condition:
	$a0
}