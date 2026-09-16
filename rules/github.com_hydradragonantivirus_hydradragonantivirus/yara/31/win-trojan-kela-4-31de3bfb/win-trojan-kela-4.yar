rule Win_Trojan_Kela_4
{
strings:
	$a0 = { 2e89162308c3b440b90000e8caffc3ba0001b9da07b440e8beffc3b440b91800ba2508e8b2ff }


condition:
	$a0
}