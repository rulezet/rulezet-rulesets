rule Win_Trojan_Agent_32814
{
strings:
	$a0 = { 88befebe9ccca2724d7f55d8ce370d8b6ed4a7b4443d44a8c72e9f8eabbdb959562d5a2ae2e769a763c744c526cab8ab6a285bbf7a255ed57c2fedda3378c8dd28 }


condition:
	$a0
}