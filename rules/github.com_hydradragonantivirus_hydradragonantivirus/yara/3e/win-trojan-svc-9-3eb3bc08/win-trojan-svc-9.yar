rule Win_Trojan_SVC_9
{
strings:
	$a0 = { 2ea3580c2e813e580c004b741b80fc3d741980fc3e }


condition:
	$a0
}