rule Win_Dropper_Agent_362
{
strings:
	$a0 = { 3c5343524950540866756e6374a76effffdffa206d616c77ab652829 }


condition:
	$a0
}