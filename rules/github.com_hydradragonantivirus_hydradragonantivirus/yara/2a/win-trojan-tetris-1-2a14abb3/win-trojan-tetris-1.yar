rule Win_Trojan_Tetris_1
{
strings:
	$a0 = { cd218be83dc8fd7733ba0001b97902b440cd21722781c50001892e2703c70625030401c7062303 }


condition:
	$a0
}