rule Win_Trojan_Kode4_1
{
strings:
	$a0 = { 803de9750d8b4d01582d19013bc17502eb2a33c933d2b800 }


condition:
	$a0
}