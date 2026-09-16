rule Win_Trojan_Silly_46
{
strings:
	$a0 = { c7088905b440b16a8bd783ea6a90e80a004fb440b1038bd7cd21c3cd21b8023dba9e00cd2193c3 }


condition:
	$a0
}