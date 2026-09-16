rule Win_Trojan_Tankard_2
{
strings:
	$a0 = { fcff741480fc3d74133d004b740e3d006c740e2eff2e7c }


condition:
	$a0
}