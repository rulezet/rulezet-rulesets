rule Win_Trojan_Tomalak_1
{
strings:
	$a0 = { 1fa14c00a3d47ca14e00a3d67cbbdeaf81f3cdab8b07488907b106d3e0bb4c00894702c7076d01be007cbf00018e }


condition:
	$a0
}