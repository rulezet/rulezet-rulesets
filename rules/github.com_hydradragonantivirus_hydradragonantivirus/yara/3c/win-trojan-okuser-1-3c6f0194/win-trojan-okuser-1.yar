rule Win_Trojan_OkUser_1
{
strings:
	$a0 = { 2efcfffcffb60f01ffb61101ffb61301c706fcfff600ffb61501be8000bf00f0b98000f3a4bfb000b82a2eab }


condition:
	$a0
}