rule Win_Spyware_6678_1
{
strings:
	$a0 = { 8bc70304242bc78038500f851b8b1fff680b731413b8001014133d }


condition:
	$a0
}