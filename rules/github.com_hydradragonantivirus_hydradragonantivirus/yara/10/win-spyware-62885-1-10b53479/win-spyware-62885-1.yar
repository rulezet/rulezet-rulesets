rule Win_Spyware_62885_1
{
strings:
	$a0 = { e8ea590000e9a4feffff8bff558bec81ec28030000a3 }

	$a1 = { 6f6e732e747874007369676e6f6e73322e747874 }


condition:
	$a0 and $a1
}