rule Win_Trojan_VGEN_687
{
strings:
	$a0 = { 0b013ec686200200fc8db60401bf0001b90400f3a4b41a8d963002cd218d961a02b44e8db6230252eb2d417368 }


condition:
	$a0
}