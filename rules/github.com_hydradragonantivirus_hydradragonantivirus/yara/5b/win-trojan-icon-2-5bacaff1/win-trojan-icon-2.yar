rule Win_Trojan_Icon_2
{
strings:
	$a0 = { ed03015053515256570e1feb00ba6601b44ecd21528d8600008d9e0001b90001badc00be0f00e80000505ab43cba }


condition:
	$a0
}