rule Win_Spyware_Banker_2708
{
strings:
	$a0 = { c6ae43e08d01a8b11c1dabb7c10d0284baf20adc39f3876de3c26de4b6a83d1d2450663a44fe822ac8b4ed9898402af098a88efc8510aa06e98f }


condition:
	$a0
}