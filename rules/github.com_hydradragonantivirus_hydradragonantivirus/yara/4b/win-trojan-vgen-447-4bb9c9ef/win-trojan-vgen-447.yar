rule Win_Trojan_VGEN_447
{
strings:
	$a0 = { 23060183be23061e7513b002b9200033d2cd26b4098d969105cd21cd20b4478db6f809b200 }


condition:
	$a0
}