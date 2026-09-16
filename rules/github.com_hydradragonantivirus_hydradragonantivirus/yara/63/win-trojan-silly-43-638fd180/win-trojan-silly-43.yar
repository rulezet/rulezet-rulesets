rule Win_Trojan_Silly_43
{
strings:
	$a0 = { 56565fe800005e81c659005632c9a5a489f25e4880c44fcd21723789f7b43ee83100b43fe82500803de974e8b8 }


condition:
	$a0
}