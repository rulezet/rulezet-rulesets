rule Win_Trojan_SC_1
{
strings:
	$a0 = { 4b8ec3a101012d0d00b104d3e88ccb03d88edbb82400cd3381fb43537503e9ac00c6063a050090c6063b050090b4 }


condition:
	$a0
}