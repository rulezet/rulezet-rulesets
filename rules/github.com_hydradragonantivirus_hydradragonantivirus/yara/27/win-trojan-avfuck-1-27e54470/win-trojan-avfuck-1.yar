rule Win_Trojan_AvFuck_1
{
strings:
	$a0 = { 03002ea3a403b440b9a60290ba0301cd21b8004233c933d2cd21b440b90300baa303cd21b80157 }


condition:
	$a0
}