rule Win_Trojan_Onkelz_2
{
strings:
	$a0 = { 1c93a8181fa1d6e4a78f1fe2edbaa0f4e4f657e1aa5ea4d6e4a78f1fd33fa61e5cf65d1eaa5ea71d }


condition:
	$a0
}