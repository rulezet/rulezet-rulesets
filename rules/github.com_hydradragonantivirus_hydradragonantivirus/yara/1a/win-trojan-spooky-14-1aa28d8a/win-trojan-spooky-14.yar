rule Win_Trojan_Spooky_14
{
strings:
	$a0 = { ffe90500b8004ccd21e2f6b401cd162e8b2e01018db6250189f7b99302e89302b8addecd2181fbadde7503e97a00 }


condition:
	$a0
}