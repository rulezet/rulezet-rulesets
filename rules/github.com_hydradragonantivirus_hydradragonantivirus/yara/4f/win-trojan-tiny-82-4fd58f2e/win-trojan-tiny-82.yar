rule Win_Trojan_Tiny_82
{
strings:
	$a0 = { 3d004b754d505351521eb8023d }


condition:
	$a0
}