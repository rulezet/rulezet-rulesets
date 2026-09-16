rule Win_Trojan_Agent_35164
{
strings:
	$a0 = { e29768f3edcf5f4aea19afb6b64a77950bcca376d383f1a6b2117e6ee47e8139ba8fc3ab18db5222eef359cbe87223b607dc6b61ec01a42292b3188418f43d18ca529cdf5d98efc8d079e2 }


condition:
	$a0
}