rule Win_Trojan_SillyRE_1
{
strings:
	$a0 = { 1e0e1fb823008ec033ffbe050058051000014439014443a69c4e4fb1ccf3a40606cb9d740f8edbbe8400a5a58c4cfe }


condition:
	$a0
}