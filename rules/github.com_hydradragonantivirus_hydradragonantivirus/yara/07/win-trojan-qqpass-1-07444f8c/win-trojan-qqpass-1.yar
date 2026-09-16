rule Win_Trojan_QQpass_1
{
strings:
	$a0 = { 94973f8098????c0b7863ef0a684fb317d01781af9ed06e1a8 }


condition:
	$a0
}