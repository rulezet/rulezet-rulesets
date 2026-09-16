rule Win_Trojan_Hupigon_534
{
strings:
	$a0 = { 73251b62ea95c1cf0d6550fa4164e7fad9aede4604f826fcefa54cd2457ecc0b2c4680811c1e88e09701e8e81957b24cac4cbea826c626e1428ea11ff35b05398ab56d8bad057c28f446bef7083a }


condition:
	$a0
}