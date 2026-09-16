rule Win_Trojan_PC_MPC_1
{
strings:
	$a0 = { e2fee800005d81ed08018db6e101bf000157a5a4c6862a061eb41a8d96ff05cd21b447b2008db6bf05cd21c686be055cb82435cd21899eba058c86bc05b4258d }


condition:
	$a0
}