rule Win_Trojan_Wypi_1
{
strings:
	$a0 = { 803e2f00ff7503e9ed001e580e593bc175092e8b36010181c60301b9cf0381c65f008bde2e8037 }


condition:
	$a0
}