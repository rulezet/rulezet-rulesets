rule Win_Trojan_SayNay_1
{
strings:
	$a0 = { 5361794e6179fae84f013e8b6e0081ed0d01fb8db69702bf0001b90900f3 }


condition:
	$a0
}