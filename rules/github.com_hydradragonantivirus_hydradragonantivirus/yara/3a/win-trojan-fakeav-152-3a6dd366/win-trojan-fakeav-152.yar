rule Win_Trojan_FakeAV_152
{
strings:
	$a0 = { 8060287f585054505357ffd558618d4424806a0039c475fa83ec80e9[0-3]fff87069 }


condition:
	$a0
}