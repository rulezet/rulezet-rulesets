rule Win_Trojan_AntiFort_1
{
strings:
	$a0 = { 54e96e4c7e7aaebe2522553e46c2ae9923b5bbcca0dda948aac86eb65076a00fbe844531e6a3dca6 }


condition:
	$a0
}