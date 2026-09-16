rule Win_Spyware_Lineage_32
{
strings:
	$a0 = { 216880c3e508f27471ca0c254d85bca20c169d6a802b93f10be235767d88e9a62d12b965b09c05a878b1a4c9f207f141a183 }


condition:
	$a0
}