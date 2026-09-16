rule Win_Dropper_Agent_33121
{
strings:
	$a0 = { 5568b570001064ff306489208d55ecb8cc700010e8cdc5ffff8b45ecb201e8ffc0ffff33c05568486d001064ff30648920baec700010b8fc700010e8fae2ffff }


condition:
	$a0
}