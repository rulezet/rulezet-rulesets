rule Win_Trojan_V_26
{
strings:
	$a0 = { e800005d81ed77001eb8fffacd213dbffa7426e848002e899e6c002e8c866e000e1f8ec1bf00018bf5b92e07fcf3a4ba }


condition:
	$a0
}