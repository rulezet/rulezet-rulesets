rule Win_Trojan_SillyC_123
{
strings:
	$a0 = { 8916ac01b41aba00fecd21b44e33c9bad301cd217310eb7a90b43ecd21b44fbad301cd21726cb8023dba1efe }


condition:
	$a0
}