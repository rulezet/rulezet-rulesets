rule Win_Trojan_FromatC_2
{
strings:
	$a0 = { 406563686f206f6666[1-200]666f726d617420633a[1-5]2f71 }


condition:
	$a0
}