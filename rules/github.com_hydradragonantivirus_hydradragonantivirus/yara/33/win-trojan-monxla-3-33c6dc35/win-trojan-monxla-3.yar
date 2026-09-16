rule Win_Trojan_Monxla_3
{
strings:
	$a0 = { 941600b42ccd2180e6077510b440b9 }


condition:
	$a0
}