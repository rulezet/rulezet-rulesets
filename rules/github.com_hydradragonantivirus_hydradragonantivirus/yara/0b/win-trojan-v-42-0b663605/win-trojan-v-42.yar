rule Win_Trojan_V_42
{
strings:
	$a0 = { 02bf4b02b92500fcacaae2fcc606540243c60655024fc60656024db411ba4b02cd213cff742abe4b02bf9502b92300fcacaae2fcbe8100bf4c02b90b00 }


condition:
	$a0
}