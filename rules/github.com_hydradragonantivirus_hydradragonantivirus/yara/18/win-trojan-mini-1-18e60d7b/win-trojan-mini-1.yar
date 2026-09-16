rule Win_Trojan_Mini_1
{
strings:
	$a0 = { 418bf3aff3a40657be4b010e59f3a4ba4501b44ecd217301cbb8023dba9e00cd2193b43fba4b015459cd21054b005033c9f7e1b442cd2159b4405a52cd21b44febd2 }


condition:
	$a0
}