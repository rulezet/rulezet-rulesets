rule Win_Trojan_Elite_1
{
strings:
	$a0 = { e800008bec83ec31836e0009bacbffe856008b76008bd683c67390bf0001a5a5b93f00b44ecd217234bae9ffb8023dcd }


condition:
	$a0
}