rule Win_Spyware_4544_1
{
strings:
	$a0 = { 3737300f5261764d2983fbfb054bccf8b9fda6d4cad0ed0ea1c1b3efff6f647563745f4e6f746966 }


condition:
	$a0
}