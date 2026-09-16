rule Win_Spyware_Sinowal_26
{
strings:
	$a0 = { 8b1d48c100100fbec050bfe0d5001057ffd385c05959894510741c }


condition:
	$a0
}