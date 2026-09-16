rule Win_Adware_Sahat_3
{
strings:
	$a0 = { 5b5341484167656e745d[0-2]5341484167656e743d[0-20]2e657865 }


condition:
	$a0
}