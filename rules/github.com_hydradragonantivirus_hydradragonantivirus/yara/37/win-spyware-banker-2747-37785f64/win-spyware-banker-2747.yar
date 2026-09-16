rule Win_Spyware_Banker_2747
{
strings:
	$a0 = { 5d1f17b7aa5f7cb441ffca57ee740e68bc17f762efac62a4f34d3913e9b89fd393a7a30a33e3cbba17ee62b1d26ac6f0d5df2ce1121b7d41e3bd718a8a49c0f6465f2098f1f5c3e29ac74b25b00d }


condition:
	$a0
}