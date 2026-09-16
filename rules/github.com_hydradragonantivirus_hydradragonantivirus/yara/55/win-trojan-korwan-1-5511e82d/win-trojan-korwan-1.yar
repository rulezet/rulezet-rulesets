rule Win_Trojan_KorWan_1
{
strings:
	$a0 = { 9c3d62f0750433c09dcf80fc117503e92d0580fc1274f8 }


condition:
	$a0
}