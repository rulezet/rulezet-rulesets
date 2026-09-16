rule Win_Trojan_Grither_3
{
strings:
	$a0 = { b440b906038bd681eaf701cd21721f3d }


condition:
	$a0
}