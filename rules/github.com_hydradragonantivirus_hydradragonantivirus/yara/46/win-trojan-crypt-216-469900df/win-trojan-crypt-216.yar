rule Win_Trojan_Crypt_216
{
strings:
	$a0 = { 558bec81ec3802000024b08d8dccffffffc7011cee3c8b66c1e10981eae2e92b63c1e81281e2 }


condition:
	$a0
}