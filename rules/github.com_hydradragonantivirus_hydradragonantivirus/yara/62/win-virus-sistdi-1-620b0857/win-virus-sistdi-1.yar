rule Win_Virus_Sistdi_1
{
strings:
	$a0 = { 5060e8000000005deb01??b9970200002e8a7d038d45198a1802df881840e2f7 }


condition:
	$a0
}