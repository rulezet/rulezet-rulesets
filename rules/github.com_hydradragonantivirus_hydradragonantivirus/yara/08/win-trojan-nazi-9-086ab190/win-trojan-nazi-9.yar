rule Win_Trojan_Nazi_9
{
strings:
	$a0 = { 57bf5c0d0e579ad80a1e027444bf8c021e57bf650d0e579ad80a1e027433bf8c021e57bf }


condition:
	$a0
}