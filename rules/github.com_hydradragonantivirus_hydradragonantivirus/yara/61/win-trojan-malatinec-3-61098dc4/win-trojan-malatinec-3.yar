rule Win_Trojan_Malatinec_3
{
strings:
	$a0 = { 5d819fc31689da8e2a030b6490854da32e938d8612b82e724dd85a6151ebd2718c1051711df9cc0d }


condition:
	$a0
}