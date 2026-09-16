rule Win_Trojan_Delima_1
{
strings:
	$a0 = { 1e06e800005d81ed0f00b82eaf929292cd2181fa78e874468cc09292488ed887ca87ca9291812e0300c00081 }


condition:
	$a0
}