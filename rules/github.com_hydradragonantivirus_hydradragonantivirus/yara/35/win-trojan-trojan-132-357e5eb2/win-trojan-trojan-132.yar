rule Win_Trojan_Trojan_132
{
strings:
	$a0 = { 99ccb44eb53fbad701cc7229b8023dba1e00cc72268bd8b43fbf1a008b0d8bd6cc8b04 }


condition:
	$a0
}