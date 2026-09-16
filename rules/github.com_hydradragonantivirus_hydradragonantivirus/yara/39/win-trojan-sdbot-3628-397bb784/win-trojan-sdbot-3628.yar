rule Win_Trojan_SdBot_3628
{
strings:
	$a0 = { f192843ad2e9352840d2584721dbb36a306bcbbe22ff79ca0568e290ffe4aff8d9c656f6b49216c15cb8cfd7d0cb2acade2156cdeca65297be5cc58248b25a65f37e229df5d9499b243b9a3ce6bd }


condition:
	$a0
}