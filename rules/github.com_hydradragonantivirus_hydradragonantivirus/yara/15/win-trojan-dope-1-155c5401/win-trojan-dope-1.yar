rule Win_Trojan_Dope_1
{
strings:
	$a0 = { b800008ed8ba2e00e81d00b419cd210441b4028ad0cd21ba4f00e80b00b401cd21b266e80200e2ddb409cd21c3000d0a }


condition:
	$a0
}