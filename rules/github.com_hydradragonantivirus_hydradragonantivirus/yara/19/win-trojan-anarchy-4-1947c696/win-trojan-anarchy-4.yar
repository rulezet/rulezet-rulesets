rule Win_Trojan_Anarchy_4
{
strings:
	$a0 = { 393b646560633cf88f05d0398f04a715c425c63ff806f6904e3c83c4c4c3f1393b06fb374e38bdff }


condition:
	$a0
}