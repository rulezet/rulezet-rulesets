rule Win_Trojan_Tiny_40
{
strings:
	$a0 = { 80fc4b75593ccc75055857f3a4cf5053521eb8023dcd2172 }


condition:
	$a0
}