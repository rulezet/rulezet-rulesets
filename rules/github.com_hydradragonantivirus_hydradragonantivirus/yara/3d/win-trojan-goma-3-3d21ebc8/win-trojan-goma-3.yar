rule Win_Trojan_Goma_3
{
strings:
	$a0 = { 01cd212efe8e1e01eb06b44fcd21721ab8023dba9e00cd218bd8b96400ba0001b440cd21b4 }


condition:
	$a0
}