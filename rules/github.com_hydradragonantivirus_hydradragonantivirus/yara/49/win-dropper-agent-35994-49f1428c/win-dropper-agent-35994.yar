rule Win_Dropper_Agent_35994
{
strings:
	$a0 = { 5589e583ec146a02ff1508a24100e8fdfeffff8db6000000008dbc27000000005589e583ec146a01ff1508a24100e8dd }


condition:
	$a0
}