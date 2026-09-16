rule Win_Trojan_RiftVilly_4
{
strings:
	$a0 = { 01e819003dea017403e905ff30c0e81100b91800baea01e80300e9f4feb440cdd3c3b442 }


condition:
	$a0
}