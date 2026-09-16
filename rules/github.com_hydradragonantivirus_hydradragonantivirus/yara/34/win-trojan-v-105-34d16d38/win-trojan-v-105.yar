rule Win_Trojan_V_105
{
strings:
	$a0 = { 5beb0990eb401900eb3c905383eb03899ff800b4fbcd213daa55746b53b430cd215b3c0272618b87fa008bebb1 }


condition:
	$a0
}