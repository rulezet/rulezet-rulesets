rule Win_Trojan_Jinx_1
{
strings:
	$a0 = { be0001561e068bec565fb800908ec0bb030126813f4a697505c6060e0101b97d0281e90001890e0901fcf3a406b825 }


condition:
	$a0
}