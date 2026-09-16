rule Win_Trojan_ECat_1
{
strings:
	$a0 = { 0107b90000b202cd13cd13cd13fec280fa1875e9be9b025052ac0ac0740b86d080ea5db402cd21 }


condition:
	$a0
}