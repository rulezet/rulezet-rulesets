rule Win_Trojan_Viruslesson2_1
{
strings:
	$a0 = { e800005e83ee038cc00510002e0384e000502effb4de001e0e1fb41aba3b0103d6cd21b44ebac40003d6cd217303e99100b8023dba590103d6cd217303e98200 }


condition:
	$a0
}