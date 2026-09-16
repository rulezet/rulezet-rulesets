rule Win_Trojan_VB_107_3
{
strings:
	$a0 = { 035f4b5550ffffffcf48636c734f506c7567696e007962645f654eda3febc2baf946ae30c960c7fe4908deb0ce1a }


condition:
	$a0
}