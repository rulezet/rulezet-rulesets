rule Win_Trojan_SillyC_196
{
strings:
	$a0 = { d2cd21b440b991018bd6cd2172a6b8004233c933d2cd21b440b90300ba9b0103d6cd21eb8f }


condition:
	$a0
}