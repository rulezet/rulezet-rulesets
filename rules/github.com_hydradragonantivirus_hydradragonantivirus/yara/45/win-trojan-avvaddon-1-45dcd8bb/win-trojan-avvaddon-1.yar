rule Win_Trojan_Avvaddon_1
{
strings:
	$a0 = { 1edb018e1e2c002e8c1ed701bba000b44acd218cc0488ed8c70601000800b82135cd210e1f891e77008c067900 }


condition:
	$a0
}