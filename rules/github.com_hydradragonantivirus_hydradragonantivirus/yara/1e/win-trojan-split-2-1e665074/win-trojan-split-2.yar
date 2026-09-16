rule Win_Trojan_Split_2
{
strings:
	$a0 = { 40b9fa00908d960901cd21725b33c933d2b80042cd21582d03008986f601b440b90400 }


condition:
	$a0
}