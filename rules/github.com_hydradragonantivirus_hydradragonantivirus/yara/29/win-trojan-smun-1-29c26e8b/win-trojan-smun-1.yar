rule Win_Trojan_Smun_1
{
strings:
	$a0 = { 1304cd12b90602d3e05007a3b87c87454ea3ad7cb8b50287454ca3ab7cc7455c68038c455ebf }


condition:
	$a0
}