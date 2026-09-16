rule Win_Trojan_Rootkit_61
{
strings:
	$a0 = { 558bec81ec2801000083a5d8feffff00576a4933c0598dbddcfeffff506a02f3abe8??0?00008bf883ffff750433c0eb428d85d8feffff565057c785d8feffff28010000e8??0?000085c0741f8b35??104000ffd63985e0feffff740f8d85d8feffff5057e8??0?0000ebe78b85f0feffff5e5fc9c3[0-200]e8??ffffff83f8 }


condition:
	$a0
}