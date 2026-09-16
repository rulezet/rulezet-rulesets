rule Win_Trojan_Gippo_1
{
strings:
	$a0 = { 53511e068cc88ed88c069304833e95042a740cb9db01be3000f7144646e2fa }


condition:
	$a0
}