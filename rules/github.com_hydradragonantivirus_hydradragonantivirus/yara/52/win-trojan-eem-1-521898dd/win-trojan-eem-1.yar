rule Win_Trojan_EEM_1
{
strings:
	$a0 = { 658bd783ea65e80a004fb440b1038bd7cd21c3cd21b8023dba9e00cd2193c3 }


condition:
	$a0
}