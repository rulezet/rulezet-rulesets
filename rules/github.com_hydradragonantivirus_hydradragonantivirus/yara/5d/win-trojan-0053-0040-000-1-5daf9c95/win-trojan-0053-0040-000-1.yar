rule Win_Trojan__0053_0040_000_1
{
strings:
	$a0 = { f6f1508bd7061f32e48bf8b800401e061fcd211f7306e88e00eb449083c2204f75e95880fc0074 }


condition:
	$a0
}