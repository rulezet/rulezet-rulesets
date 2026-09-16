rule Win_Trojan_SillyRC_12
{
strings:
	$a0 = { 1e063d004b75696a6007b443cd2180e1feb80143cd21b8 }


condition:
	$a0
}