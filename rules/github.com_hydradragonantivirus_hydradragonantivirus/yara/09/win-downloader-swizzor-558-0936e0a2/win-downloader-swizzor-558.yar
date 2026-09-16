rule Win_Downloader_Swizzor_558
{
strings:
	$a0 = { 8ec667c6f51ae02785f427381558d7a537089743bb9bad420db4b216cee78a53d94dfde9b90c00b41cbda747ad328296cd10300c9b97ce3b20fbd503c71edbd35e51ec9276e87957b4376987 }


condition:
	$a0
}