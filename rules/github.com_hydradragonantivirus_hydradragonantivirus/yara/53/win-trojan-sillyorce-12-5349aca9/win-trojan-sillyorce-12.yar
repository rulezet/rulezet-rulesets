rule Win_Trojan_SillyORCE_12
{
strings:
	$a0 = { 80fc3e751f1e52515033c933d2b80042cd32b14cba00010e1fb440cd3258cd32595a1fcfea }


condition:
	$a0
}