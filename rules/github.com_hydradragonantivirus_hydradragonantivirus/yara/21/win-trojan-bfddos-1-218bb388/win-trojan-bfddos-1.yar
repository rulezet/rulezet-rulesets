rule Win_Trojan_Bfddos_1
{
strings:
	$a0 = { 741c99bdde0e232bd4026449a8a47ef620491306554d1f60e3e58e4974b58ff5e58d1e423e51 }


condition:
	$a0
}