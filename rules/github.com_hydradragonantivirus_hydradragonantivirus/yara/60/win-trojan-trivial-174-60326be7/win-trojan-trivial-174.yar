rule Win_Trojan_Trivial_174
{
strings:
	$a0 = { 2a2e652ab44e89f2cd21ba9e00b82e5bf2aeffafa0028f058bcecd2193b44073e5c3 }


condition:
	$a0
}