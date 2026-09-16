rule Win_Trojan_AntiBasic_1
{
strings:
	$a0 = { 33c9b80143cd217219b8013dcd2172128bd8ba1602b440b94900cd217204b43ecd21ba00ff }


condition:
	$a0
}