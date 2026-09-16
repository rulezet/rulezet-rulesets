rule Win_Trojan_Small_4076
{
strings:
	$a0 = { 5589e5682a02000050e8170000005deb4381c5ff????fff7d501dd89ef81c7dc070000eb129283c40c5deb5283c40c5653555731 }


condition:
	$a0
}