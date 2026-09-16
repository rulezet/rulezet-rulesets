rule Win_Trojan_Deltreey_2
{
strings:
	$a0 = { 64656c74726565202f7920633a5c77696e646f77735c636f6d6d616e645c2a2e2a203e68692e6c6f67 }


condition:
	$a0
}