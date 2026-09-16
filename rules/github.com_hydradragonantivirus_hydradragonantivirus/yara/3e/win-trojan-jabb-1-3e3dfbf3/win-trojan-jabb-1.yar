rule Win_Trojan_Jabb_1
{
strings:
	$a0 = { 1e01c747e0cd21c747e2eb1495b8fe4bc60717ebe8fa33c0f6e488077400be7002b99800fc }


condition:
	$a0
}