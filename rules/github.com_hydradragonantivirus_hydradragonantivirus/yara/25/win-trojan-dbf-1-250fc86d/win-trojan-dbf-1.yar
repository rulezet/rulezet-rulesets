rule Win_Trojan_DBF_1
{
strings:
	$a0 = { 9b18221e8e1cfc0aa5e96da5efa57852ce5ae73b8c49759b18221e8cf002541a8c3dd3361ad4a01f }


condition:
	$a0
}