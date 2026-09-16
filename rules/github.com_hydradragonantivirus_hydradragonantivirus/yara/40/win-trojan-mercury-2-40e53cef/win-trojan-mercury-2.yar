rule Win_Trojan_Mercury_2
{
strings:
	$a0 = { 0a01c7864a040100b41a8d96a004cd21e8dc008db694038dbe4c04b907008a05860486054647e2f6b44732d28d }


condition:
	$a0
}