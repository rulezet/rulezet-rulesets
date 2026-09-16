rule Win_Trojan_Fear_staticsig_2
{
strings:
	$a0 = { 985eb6a0b3dba4840e6147909fc7bbf85ec0193fbc239d481c85865c8d5dc438c2468a0ef8df4cef7ce6b735db8808894fdf82a5bbf5d20f0ad95112c303 }


condition:
	$a0
}