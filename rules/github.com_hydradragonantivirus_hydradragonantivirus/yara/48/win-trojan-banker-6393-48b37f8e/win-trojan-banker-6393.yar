rule Win_Trojan_Banker_6393
{
strings:
	$a0 = { 723a5c7472696f7261335c7379735c746573742e6c7074 }


condition:
	$a0
}