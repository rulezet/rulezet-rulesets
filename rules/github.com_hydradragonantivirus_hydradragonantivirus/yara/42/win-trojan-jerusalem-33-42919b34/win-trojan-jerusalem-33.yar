rule Win_Trojan_Jerusalem_33
{
strings:
	$a0 = { cd2180fc007514bf00018bf781c6a7058b0e0c01b4f1cd21e9a4048cc88ed0bca5062e8c0628012e8c064a012e8c }


condition:
	$a0
}