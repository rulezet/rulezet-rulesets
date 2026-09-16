rule Win_Trojan_Trivial_50
{
strings:
	$a0 = { 030083c7088905b440b1688bd783ea68e80a004fb440b1038bd7cd21c3cd21b8023dba9e00cd21 }


condition:
	$a0
}