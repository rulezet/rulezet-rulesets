rule Win_Trojan_Bancos_943
{
strings:
	$a0 = { 1e42cc2b336ee50b2ba47067e94721739b801f960a81cae70afd6711be98b6b31edcd460f9dc64b653dfae285b11cd99ced57d561a7d1a060d715229935b9730a4bb7b7f26fcf28b6ceef34f3eab }


condition:
	$a0
}