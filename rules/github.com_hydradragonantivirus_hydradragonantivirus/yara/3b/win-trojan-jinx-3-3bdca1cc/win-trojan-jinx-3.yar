rule Win_Trojan_Jinx_3
{
strings:
	$a0 = { be0001561e068bec565fb800908ec0bb030126813f4a697505c6060e0101b9360381e90001890e0901fcf3a406b8de }


condition:
	$a0
}