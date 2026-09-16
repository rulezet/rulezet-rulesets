rule Win_Trojan_MagicHound_5859367_0
{
strings:
	$a0 = { 8b4424??569983e20f8d4c24??03c28bf0c1fe0446c1e604e8 }


condition:
	$a0
}