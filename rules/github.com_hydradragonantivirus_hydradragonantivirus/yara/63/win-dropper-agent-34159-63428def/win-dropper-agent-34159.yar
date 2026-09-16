rule Win_Dropper_Agent_34159
{
strings:
	$a0 = { 81c7ea5ef8065481efea5ef806893c24 }


condition:
	$a0
}