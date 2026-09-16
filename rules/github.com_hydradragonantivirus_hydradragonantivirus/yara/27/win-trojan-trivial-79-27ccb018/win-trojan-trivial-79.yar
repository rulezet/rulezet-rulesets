rule Win_Trojan_Trivial_79
{
strings:
	$a0 = { ed03012ec686b101008d96ab01b44ee80e00cd2000bf0001578db61701a5a4c3b90700b44ecd2172f6b8023d8d96 }


condition:
	$a0
}