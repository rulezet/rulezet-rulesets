rule Win_Trojan_NoHope_1
{
strings:
	$a0 = { b90300cd217267538bda803fe95b744bb8024233c933d2cd21725350b4408bd683ea0bb90101cd21 }


condition:
	$a0
}