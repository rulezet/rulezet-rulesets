rule Win_Trojan_Agent_35781
{
strings:
	$a0 = { d3c08ad302f380d4180ae8d2da13cb12f4b9d975cedc80c0e98bd133f8e93803 }


condition:
	$a0
}