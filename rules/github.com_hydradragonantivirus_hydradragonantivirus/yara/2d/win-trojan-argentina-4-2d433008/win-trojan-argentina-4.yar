rule Win_Trojan_Argentina_4
{
strings:
	$a0 = { f07fe17ff0e1e8e1e8e1f07f7f169ded247f04ec22cf7f87e1ef2c7f51505465eb7f65ea7f65e87f }


condition:
	$a0
}