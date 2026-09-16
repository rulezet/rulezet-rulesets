rule Win_Trojan_Agent_32833
{
strings:
	$a0 = { f462cce4749623d5eae8305a6987bcf026ddacc5704763d8290bb37aae75ed0cf702e80817b15b9cdcdf535b0c96d6bb57300a35ec26c8286fd9434fb341d05579 }


condition:
	$a0
}