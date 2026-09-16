rule Win_Trojan_Burma_9
{
strings:
	$a0 = { 01faba4559cd16c35053515256571654b800b88ec0c706 }


condition:
	$a0
}