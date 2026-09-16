rule Win_Trojan_Peed_237
{
strings:
	$a0 = { ba6774540056fc587342ff1557744500e8 }


condition:
	$a0
}