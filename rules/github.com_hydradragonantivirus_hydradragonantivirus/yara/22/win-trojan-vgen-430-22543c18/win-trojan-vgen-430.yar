rule Win_Trojan_VGEN_430
{
strings:
	$a0 = { 0e0e1f07b8023dba6102cd2193b43fbe6a0289f2b90002cd215683c614bf8101a5a58345fe105e836c0810c744 }


condition:
	$a0
}