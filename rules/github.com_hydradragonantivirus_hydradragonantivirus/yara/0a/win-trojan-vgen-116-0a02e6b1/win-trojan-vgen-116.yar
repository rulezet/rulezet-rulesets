rule Win_Trojan_VGEN_116
{
strings:
	$a0 = { fcff09ba2affb41acd21e83500752fe88900ba8000b41acd218b1efcff8b874400a300018b874600a302018a8748 }


condition:
	$a0
}