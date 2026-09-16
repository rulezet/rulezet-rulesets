rule Win_Trojan_Dref_3
{
strings:
	$a0 = { 68c81740009c60e940f8ffff50e8020000009090ff2530204000cccc[0-96]4b45524e454c33322e444c4c }


condition:
	$a0
}