rule Win_Trojan_Disk_1
{
strings:
	$a0 = { 8607a90088078a088c09c35589e583ec0ca1561a6202feff7604e8004469287329636b20416c6d69 }


condition:
	$a0
}