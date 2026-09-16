rule Win_Spyware_Banker_2695
{
strings:
	$a0 = { fefc2e7871cc7f19f2ae3baa5928a71fc84b2b13abef2ac1273c2c07f1c5439f860f03017ea7721a11b946830bbb6302c26aad9a6a90a44f5418 }


condition:
	$a0
}