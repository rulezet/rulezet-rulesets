rule Win_Trojan_Dead_1
{
strings:
	$a0 = { bf0000b90d00fcf3a4b440b9520533d2e8f4fd7303e9ce00b8004233c933d2e8e5fd7303e9 }


condition:
	$a0
}