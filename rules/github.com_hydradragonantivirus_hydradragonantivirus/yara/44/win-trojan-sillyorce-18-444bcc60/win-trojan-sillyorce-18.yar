rule Win_Trojan_SillyORCE_18
{
strings:
	$a0 = { 8ec1bfb00426390d7517be0001b146fcf3a48ed966b8d6040000668706840066abcb80fc4b751a601eb8023d }


condition:
	$a0
}