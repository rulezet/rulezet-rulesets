rule Win_Trojan_Riot_14
{
strings:
	$a0 = { ed0301e81700eb27900000e80f00b440b93b018d960001cd21e80100c38b9e0e018db63401b98400311c4646e2fa }


condition:
	$a0
}