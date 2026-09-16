rule Win_Trojan_Runme_2
{
strings:
	$a0 = { 9a00003f015589e531c09acd023f01e8dbede8d5fe5d31c09a16013f01558bec83ec501ec5760c8d7eb01607fcac3c4f }


condition:
	$a0
}