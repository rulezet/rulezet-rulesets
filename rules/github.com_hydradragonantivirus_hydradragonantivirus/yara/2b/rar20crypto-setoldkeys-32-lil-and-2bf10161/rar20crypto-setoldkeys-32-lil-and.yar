rule Rar20Crypto_SetOldKeys__32_lil_AND_
{
strings:
	$a0 = { 79b8a3d3[0-20]f7126d3f[0-20]35a21575[0-20]23f1e7a4 }

condition:
	$a0
}