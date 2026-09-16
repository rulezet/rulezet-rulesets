rule Win_Trojan_E_17
{
strings:
	$a0 = { 411fe2f9b801438d95a301cd21b8023dcd218bd8b43fb1038d95c201cd218bf2803ce97531fe0c46b802422bc9 }


condition:
	$a0
}