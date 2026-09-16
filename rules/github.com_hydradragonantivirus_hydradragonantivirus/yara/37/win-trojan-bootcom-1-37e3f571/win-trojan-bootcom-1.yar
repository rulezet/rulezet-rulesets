rule Win_Trojan_BootCOM_1
{
strings:
	$a0 = { 0e16585933c87537b801028d9e580241ba8000cd1326803fe87416b8010341cd138d76fd8bfbb95001f3a4b8010341 }


condition:
	$a0
}