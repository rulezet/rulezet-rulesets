rule Win_Dropper_Agent_34228
{
strings:
	$a0 = { 8bd88d4dc8ba64471413b884471413e829f3ffff8b45c8e82dedffff50a17c66141350e8edf1ffff }


condition:
	$a0
}