rule Win_Trojan_Lame_8
{
strings:
	$a0 = { 032d0500a30301b43fb905008d961a03cd2181be1a0389f6742132c0e85500ba0001b90500 }


condition:
	$a0
}