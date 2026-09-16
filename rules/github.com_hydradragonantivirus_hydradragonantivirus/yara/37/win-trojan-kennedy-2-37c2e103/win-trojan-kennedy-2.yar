rule Win_Trojan_Kennedy_2
{
strings:
	$a0 = { 17007204b44febf38bc5050301ffe0 }


condition:
	$a0
}