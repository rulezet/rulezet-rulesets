rule Win_Trojan_Cryptor_1
{
strings:
	$a0 = { ea77343de803722f2d030089866d038db651028dbe670cb9160ae85408b4408bd7cd21b80042 }


condition:
	$a0
}