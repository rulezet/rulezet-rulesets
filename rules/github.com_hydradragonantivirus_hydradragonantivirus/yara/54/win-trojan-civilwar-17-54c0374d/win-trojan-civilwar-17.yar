rule Win_Trojan_CivilWar_17
{
strings:
	$a0 = { fca07505b801009dcf1e0657565053515280fc3d74133d }


condition:
	$a0
}