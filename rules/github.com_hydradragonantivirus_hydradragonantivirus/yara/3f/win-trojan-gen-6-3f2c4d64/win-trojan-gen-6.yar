rule Win_Trojan_Gen_6
{
strings:
	$a0 = { 038dbe8b058db60601e87d0051b90300b4408d96ef04cd21b440598d968b05cd2132c0e82900 }


condition:
	$a0
}