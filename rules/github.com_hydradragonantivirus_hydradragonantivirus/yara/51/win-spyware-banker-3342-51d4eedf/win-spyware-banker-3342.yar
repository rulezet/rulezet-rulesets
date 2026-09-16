rule Win_Spyware_Banker_3342
{
strings:
	$a0 = { f0ad4b3d83fba8412f7aa4bf0d00e744427a2b3279bc3f4bae13c15e4b8e3d87e64ae98aaae97ee63d7f7740f2bdf137b0433afac0ef671e9d1a05393f7e2159e6d85614432e }


condition:
	$a0
}