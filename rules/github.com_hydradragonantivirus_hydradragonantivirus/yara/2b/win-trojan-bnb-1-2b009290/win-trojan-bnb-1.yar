rule Win_Trojan_BNB_1
{
strings:
	$a0 = { 01b80103b90100cd135f5e57ba6c0003d6bf830003feb456cd21ba760003d6bf920003feb456 }


condition:
	$a0
}