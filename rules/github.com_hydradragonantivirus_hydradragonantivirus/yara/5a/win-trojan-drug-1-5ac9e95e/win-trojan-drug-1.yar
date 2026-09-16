rule Win_Trojan_Drug_1
{
strings:
	$a0 = { d903b91800b43fcd21c3e810007301c30e1fbad903b91800b440cd21c3b8004233d233c9cd21c3 }


condition:
	$a0
}