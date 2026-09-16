rule Win_Trojan_Startpage_393
{
strings:
	$a0 = { ff351030001068001000106a05ff1558200010a300400010c3 }


condition:
	$a0
}