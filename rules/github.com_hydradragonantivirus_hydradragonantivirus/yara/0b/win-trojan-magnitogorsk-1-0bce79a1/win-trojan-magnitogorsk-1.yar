rule Win_Trojan_Magnitogorsk_1
{
strings:
	$a0 = { 8b851f003dffff7413be3e0003f7b9 }


condition:
	$a0
}