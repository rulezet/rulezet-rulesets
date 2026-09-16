rule Win_Trojan_Bzz_7
{
strings:
	$a0 = { 8b0ef30381c1bb02bac703cd21b80042e83500b440b90300baba03cd218b0ec3038b16c503b8 }


condition:
	$a0
}