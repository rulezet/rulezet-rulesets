rule Win_Trojan_MadMax_1
{
strings:
	$a0 = { b440cd2133c933d2b80042cd218b0efa0280c91f890efa02bafe02b90300b440cd2183fb }


condition:
	$a0
}