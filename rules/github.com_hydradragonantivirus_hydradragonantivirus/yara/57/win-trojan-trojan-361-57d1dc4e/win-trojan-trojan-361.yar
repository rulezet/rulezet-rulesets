rule Win_Trojan_Trojan_361
{
strings:
	$a0 = { 074a62328ed893abb76ce08bdea0fa460494fea12d4aeea858654c4d4d9f06328f3e0ee0dd6c5a29c4baef670176f042f9aa2ef5be7d36ca29d07717c7b6133eafcd235f3f2d583d237010d85dd4f6009bdef2 }


condition:
	$a0
}