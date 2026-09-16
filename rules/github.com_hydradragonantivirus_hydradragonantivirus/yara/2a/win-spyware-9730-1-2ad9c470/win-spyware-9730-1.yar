rule Win_Spyware_9730_1
{
strings:
	$a0 = { 23c3f5e80700000003c4e9090000002b }


condition:
	$a0
}