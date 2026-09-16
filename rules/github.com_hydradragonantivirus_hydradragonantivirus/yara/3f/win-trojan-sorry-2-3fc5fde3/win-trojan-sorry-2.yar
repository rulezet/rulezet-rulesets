rule Win_Trojan_Sorry_2
{
strings:
	$a0 = { bf00015756b90500f3a45f57c64505005e83ee03061eba60008ec233ffb900019026803de8741e57f3a41fbe8400a5 }


condition:
	$a0
}