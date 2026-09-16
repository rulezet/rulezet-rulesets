rule Win_Trojan_R_80
{
strings:
	$a0 = { b440b9cd018d960501cd21e80100c33e8b9618018db65901b9c20031144646e2fac3b41acd }


condition:
	$a0
}