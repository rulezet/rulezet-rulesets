rule Win_Trojan_R_38
{
strings:
	$a0 = { eb75909090ffffb430bbf103cd2181fb2923750b8bec8b6e00c3ea9e101c015d3c037253b448bb7e00cd2173 }


condition:
	$a0
}