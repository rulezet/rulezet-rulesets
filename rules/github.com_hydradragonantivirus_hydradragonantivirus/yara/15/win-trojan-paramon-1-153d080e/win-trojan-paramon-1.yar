rule Win_Trojan_Paramon_1
{
strings:
	$a0 = { 999975038cc8cf3d004b74052eff2e8202fa2e8c16e602 }


condition:
	$a0
}