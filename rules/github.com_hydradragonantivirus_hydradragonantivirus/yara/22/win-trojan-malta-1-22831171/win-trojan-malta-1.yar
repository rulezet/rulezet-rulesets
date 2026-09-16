rule Win_Trojan_Malta_1
{
strings:
	$a0 = { 579a830a2801e824febf52001e579af2000501eba289ec5dc2040007433a5c444f535c09 }


condition:
	$a0
}