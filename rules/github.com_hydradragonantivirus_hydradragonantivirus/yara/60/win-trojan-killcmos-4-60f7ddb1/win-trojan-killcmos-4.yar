rule Win_Trojan_KillCMOS_4
{
strings:
	$a0 = { 7479206e756c0d0a6563686f20b0ff33d2e670508ac2e67158fec8b3ff3ac37df0fec23ad37deab02ee670e671c33e433a5c7465726d6f2e636f6d0d0a63645c0d0a7465726d6f0d0a }


condition:
	$a0
}