rule Win_Spyware_Banker_1446
{
strings:
	$a0 = { 4d737ab11a871ea41ace85fa141386ca2aed62748fe3ca46dc1385fadd3cc07c8d9e8ae9e05c31ab784331da440909242437fd649d7c0ada256d521abea3e7e03893674e }


condition:
	$a0
}