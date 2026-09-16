rule Win_Trojan_SillyRC_33
{
strings:
	$a0 = { 4b7403e9aa005053511e52068bdab90200b02e380774 }


condition:
	$a0
}