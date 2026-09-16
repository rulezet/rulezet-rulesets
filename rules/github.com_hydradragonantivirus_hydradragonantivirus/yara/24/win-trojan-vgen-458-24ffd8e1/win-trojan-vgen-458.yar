rule Win_Trojan_VGEN_458
{
strings:
	$a0 = { 846c0350e8720083ec0e50b8023d8d945401cd218bd8598d946c03b440cd2133c9b440cd21b4 }


condition:
	$a0
}