rule Win_Trojan_Tavdig_1
{
strings:
	$a0 = { 7661626d753f0053686e627261206b68776479616a646f62206d647178707a6c }


condition:
	$a0
}