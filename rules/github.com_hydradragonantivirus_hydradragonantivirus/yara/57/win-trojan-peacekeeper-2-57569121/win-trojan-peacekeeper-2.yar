rule Win_Trojan_PeaceKeeper_2
{
strings:
	$a0 = { 3dadde75038bd8cf3daede741c3d004b742080fc11743880fc1274332eff2e????cf9c }


condition:
	$a0
}