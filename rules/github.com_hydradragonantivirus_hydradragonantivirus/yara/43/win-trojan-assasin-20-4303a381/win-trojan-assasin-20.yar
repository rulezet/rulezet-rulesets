rule Win_Trojan_Assasin_20
{
strings:
	$a0 = { 68386a4200683c6a4200e85200feff85c0760c6a006a006a1050e8fa00feff }


condition:
	$a0
}