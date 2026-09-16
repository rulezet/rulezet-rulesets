rule Win_Trojan_LightGeneral_3
{
strings:
	$a0 = { 038d9c27001e560e538cc80500108ec0bbc50150530e1fbf0001b9c304fcf3a4cb5b1f1e07ba8000b41acd212e }


condition:
	$a0
}