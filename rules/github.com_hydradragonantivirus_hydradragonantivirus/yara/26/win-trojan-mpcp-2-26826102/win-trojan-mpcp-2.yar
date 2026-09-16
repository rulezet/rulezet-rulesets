rule Win_Trojan_MPCP_2
{
strings:
	$a0 = { 8d96960259cd21b8024233c999cd21b4408d960301b96301cd21b801578b8e80028b968202cd }


condition:
	$a0
}