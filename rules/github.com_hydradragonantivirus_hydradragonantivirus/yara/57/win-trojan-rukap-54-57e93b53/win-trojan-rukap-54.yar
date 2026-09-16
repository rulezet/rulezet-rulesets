rule Win_Trojan_Rukap_54
{
strings:
	$a0 = { 3c7c394322b6f723b5b71058946a86acafe2b6e4a18cb6d22845e2ad41cf9e399b2a82fc925643cfbecc4d6cad49cfe50eafc229a69266bd38903dc40c0d33e85bccacf88237af15 }


condition:
	$a0
}