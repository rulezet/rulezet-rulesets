rule Win_Trojan_VGEN_416
{
strings:
	$a0 = { 33c08ed8b47cfa1e178be0fb1e501e5f505e56bb4c00c407a33c7d8c063e7da1130448a31304b106d3e0c707500189 }


condition:
	$a0
}