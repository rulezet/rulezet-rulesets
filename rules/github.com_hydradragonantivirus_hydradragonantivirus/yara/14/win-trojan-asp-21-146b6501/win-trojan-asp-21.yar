rule Win_Trojan_ASP_21
{
strings:
	$a0 = { 6d6574686f643d22706f737422[0-198]3e3c253d776a253e }

	$a1 = { 2e77726974652022cdeab3c9a3a122 }


condition:
	$a0 and $a1
}