rule Win_Trojan_DiskEraser_3
{
strings:
	$a0 = { c08ed0bc007c8bf45007501ffbe800005e83ee038d7c16b95e00fc2e81359a38afe2f8 }


condition:
	$a0
}