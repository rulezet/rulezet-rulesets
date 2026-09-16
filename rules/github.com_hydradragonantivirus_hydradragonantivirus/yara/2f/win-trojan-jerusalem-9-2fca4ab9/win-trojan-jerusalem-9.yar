rule Win_Trojan_Jerusalem_9
{
strings:
	$a0 = { c805100050b8fa0150cbb4ffcd2180fcff745980fc0c74208cc00510002e010630002e01062a00fa2e8b262c002e8e }


condition:
	$a0
}