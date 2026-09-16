rule Win_Downloader_Zlob_2314
{
strings:
	$a0 = { 883753dcdeaaea2a6e743a71c5727b8904223439c61879a18f5ed276056bc2bdca1d5909c883ca80c6ddd8ad837140d810ff5cab806b1991d6fe4b71040ebcee5dac8b391b8331d2f403e383b6ed }


condition:
	$a0
}