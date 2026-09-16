rule Win_Trojan_SVC_3
{
strings:
	$a0 = { 2ea3270b2e813e270b004b741b80fc3d741980fc3e }


condition:
	$a0
}