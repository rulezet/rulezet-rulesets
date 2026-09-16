rule Win_Trojan_U_92
{
strings:
	$a0 = { 5cc1a2b801303092309d017c8f919ec100b10b93c4a1205a08b0019401c18ca13993827c489c3453 }


condition:
	$a0
}