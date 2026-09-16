rule Win_Trojan_Pixel_18
{
strings:
	$a0 = { b800f0908ec026a0feff3cfc7545b42acd2180fa03753c33dbb003b91300cd2659ba2c01b409cd21eb29908faeacada8e2a520ae2082889093918095212121 }


condition:
	$a0
}