rule Win_Trojan_Mantis_3
{
strings:
	$a0 = { 280153e839005bb4408d960301b93201cd2153e802005bc38db699018b9e2801b94e00311c46 }


condition:
	$a0
}