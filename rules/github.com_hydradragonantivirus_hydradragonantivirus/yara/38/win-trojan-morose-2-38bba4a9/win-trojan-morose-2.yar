rule Win_Trojan_Morose_2
{
strings:
	$a0 = { 24c3b44eba535c03d5b941dee90400f028f01ccd21b5a7bf000102998090bebc5c7009e90600ee78ee6eee6403f5d1cbb90300fcf3a4e90500b8edb0eda4b8b10681f0b33bba9e00cd2173 }


condition:
	$a0
}