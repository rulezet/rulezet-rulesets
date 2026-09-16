rule _SimplePack_V11X_Method2__bagie__Sign_by_fly_
{
	meta:
		description = "SimplePack V1.1X (Method2) -> bagie ! Sign by fly"
	strings:
		$0 = {4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00}
	condition:
		$0
}