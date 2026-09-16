rule Win_Trojan_Nethel_2
{
strings:
	$a0 = { 8d85f8fdffff50e8ca020000598d85f8fdffff5950ff15142040008d85f8fdffff50e8b5feffff593bf757577407687c304000eb05 }


condition:
	$a0
}