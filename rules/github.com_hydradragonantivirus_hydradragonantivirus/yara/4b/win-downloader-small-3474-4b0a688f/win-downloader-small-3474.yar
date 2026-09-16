rule Win_Downloader_Small_3474
{
strings:
	$a0 = { 7e796ed08b1c3122096874c57047c32a5a3b2a6f98f663ec6de261ee64acdc3f202ff3f7bb36b622165b66433653465063 }


condition:
	$a0
}