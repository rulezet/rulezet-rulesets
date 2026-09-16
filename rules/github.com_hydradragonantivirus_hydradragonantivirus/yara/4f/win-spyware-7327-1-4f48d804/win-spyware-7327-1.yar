rule Win_Spyware_7327_1
{
strings:
	$a0 = { 52535b52ff04245a8bd48b1283c40433c0f9e8 }


condition:
	$a0
}