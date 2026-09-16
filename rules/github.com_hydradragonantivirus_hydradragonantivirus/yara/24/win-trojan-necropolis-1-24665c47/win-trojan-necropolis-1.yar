rule Win_Trojan_Necropolis_1
{
strings:
	$a0 = { 060609af08b401ff1e4c009d2ec7060609ab08b40bff }


condition:
	$a0
}