rule Win_Trojan_DarkAvenger_5
{
strings:
	$a0 = { 5e81ee210b8bfe56501e060e1f0e07b200b91e0bac5188d1d2c8fec259aae2f4071f58c3 }


condition:
	$a0
}