rule Win_Trojan_Trivial_290
{
strings:
	$a0 = { 4eba2a01cd21721dba9e00525e837cfe007712b8013dcd21720b938b4cfcb440ba0001cd21cd202a2e45584500 }


condition:
	$a0
}