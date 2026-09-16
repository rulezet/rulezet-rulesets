rule Win_Trojan_VGEN_238
{
strings:
	$a0 = { 8ed88ec0b409ba8001cd21b40abab701cd21b5008a0eb801beb901bfe101f3a4bae001b43bcd217202cd20053000 }


condition:
	$a0
}