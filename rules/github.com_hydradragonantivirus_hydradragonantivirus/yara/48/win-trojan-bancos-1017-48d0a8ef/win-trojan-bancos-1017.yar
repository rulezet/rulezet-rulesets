rule Win_Trojan_Bancos_1017
{
strings:
	$a0 = { c30a18a5c7edf64edf7c93ccb2e8be909218bd876c71e42f1fdb3c1d232a2836d7e983e2ee37fcddfc8c6f2af06281a7a71ec2bac9349eda729c74f8ac058f26 }


condition:
	$a0
}