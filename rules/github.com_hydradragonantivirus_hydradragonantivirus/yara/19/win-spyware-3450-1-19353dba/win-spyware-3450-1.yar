rule Win_Spyware_3450_1
{
strings:
	$a0 = { 5050330c2483c4085033c82bc65840e84c }


condition:
	$a0
}