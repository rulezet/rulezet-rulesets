rule Win_Trojan_Radyum_3
{
strings:
	$a0 = { b9550181374b1c83c302e2f790a31c4b41caf1501d78dcc5c48f1adb1c6590cda04832c29af51fc68a301ec20a }


condition:
	$a0
}