rule Win_Trojan_MacGyver_3
{
strings:
	$a0 = { e3f7e10bd275053d3a0472ee8bd6b8023de8010172e493521e0e1fe540a35b03b8024233c933d2 }


condition:
	$a0
}