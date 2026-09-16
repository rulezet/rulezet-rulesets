rule Win_Trojan_BackForm_1
{
strings:
	$a0 = { 22cd137203e97102c6061f08000e1fb8003dba2408 }


condition:
	$a0
}