rule Win_Trojan_Pepe_1
{
strings:
	$a0 = { 8933824bb70bc97509b454cd21e90f0013e9e81cff95e9c6ff }


condition:
	$a0
}