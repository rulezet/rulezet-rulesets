rule Win_Spyware_3462_1
{
strings:
	$a0 = { 565e535383c404525283c404890c24e8 }


condition:
	$a0
}