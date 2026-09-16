rule Win_Trojan_Gliss_1
{
strings:
	$a0 = { d85f578b45fc052700bf04018905b90600ba0001b440 }


condition:
	$a0
}