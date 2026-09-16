rule Win_Trojan_Bancos_1803
{
strings:
	$a0 = { 5d67aa52844ab37b950bbc18582e57c0344ef3fe0dbd0a2259e9fb5b7e57156e9379e2d95576b41023194f9748eabc484791a8e3fd4c496ee172e42fe08cbebfea58a5a77a03 }


condition:
	$a0
}