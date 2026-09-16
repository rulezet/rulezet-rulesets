rule Win_Trojan_June8_1
{
strings:
	$a0 = { fa8d863a0126a30400268c0e06000e8d86550150cf }


condition:
	$a0
}