rule Win_Trojan_Mephisto_13
{
strings:
	$a0 = { 2e8dbe0e01b94a022e8bb6ac052e31354747e2f961c39dea }


condition:
	$a0
}