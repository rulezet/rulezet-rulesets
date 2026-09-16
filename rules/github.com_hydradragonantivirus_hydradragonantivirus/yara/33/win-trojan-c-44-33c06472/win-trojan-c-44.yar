rule Win_Trojan_C_44
{
strings:
	$a0 = { 3dba020133c9cd217329b43cba020133c9cd21723b93b440b9fe00ba0001cd21b43ecd21b800 }


condition:
	$a0
}