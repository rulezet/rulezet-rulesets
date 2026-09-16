rule Win_Downloader_Small_3180
{
strings:
	$a0 = { f37f357c5a80205d05f7010005e4271f07e23c60fcdfc9755cc0e13c2380604105bff7a7fadb3a156bf3741e2bf86c1005d70b186af7722f0b17fe11fed6640e76166fda50d2 }


condition:
	$a0
}