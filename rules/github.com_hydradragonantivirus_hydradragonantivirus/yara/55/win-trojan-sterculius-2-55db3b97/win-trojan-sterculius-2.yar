rule Win_Trojan_Sterculius_2
{
strings:
	$a0 = { b440b9180190bae001e884ffb8004233c999e87bffb440b90400ba3902908bf2896c01e86aff }


condition:
	$a0
}