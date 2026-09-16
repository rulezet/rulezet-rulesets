rule Win_Trojan_Becontr_1
{
strings:
	$a0 = { 00002f6274732f32332e7068703f676574636e66673d0000 }


condition:
	$a0
}