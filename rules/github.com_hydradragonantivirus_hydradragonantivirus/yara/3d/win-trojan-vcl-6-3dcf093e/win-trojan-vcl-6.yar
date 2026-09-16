rule Win_Trojan_VCL_6
{
strings:
	$a0 = { 8dbe0203b9f302813527d54747e2f8c3 }


condition:
	$a0
}