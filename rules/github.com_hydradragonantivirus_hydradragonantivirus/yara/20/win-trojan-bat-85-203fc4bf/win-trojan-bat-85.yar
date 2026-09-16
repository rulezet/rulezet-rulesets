rule Win_Trojan_BAT_85
{
strings:
	$a0 = { 636f70792070656e63696c2e657865[0-9]5c77696e2e657865 }

	$a1 = { 5c72756e5d203e3e633a5c7a2e726567 }


condition:
	$a0 and $a1
}