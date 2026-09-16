rule Win_Trojan_Trivial_449
{
strings:
	$a0 = { 380039c337a48c40acffb6738bce8c37138d358cb040ac1e659e8d39b340ac39c26669a7c4c2d9cca7a3cec2c08d39cd378d8c65898db148cd21b93400be030180348d46e2fa }


condition:
	$a0
}