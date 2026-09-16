rule Win_Trojan_JDC_2
{
strings:
	$a0 = { e80000588be8b807012be8582e89863a01e8000058050e00502e8b863a01e983139090e9a300 }


condition:
	$a0
}