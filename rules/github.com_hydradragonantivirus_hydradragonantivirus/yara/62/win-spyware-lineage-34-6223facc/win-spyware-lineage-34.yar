rule Win_Spyware_Lineage_34
{
strings:
	$a0 = { 8e51897fe5493d99862463f5e8fa05bdf2b2b08d88bf06636cf7500edbbe5e3c695cdbf61421769272f6b457f79a3e5f3fbe }


condition:
	$a0
}