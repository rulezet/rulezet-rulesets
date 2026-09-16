rule Win_Spyware_4094_1
{
strings:
	$a0 = { 535b565683c404575f565683c40483c404891c2457681f4228735f }


condition:
	$a0
}