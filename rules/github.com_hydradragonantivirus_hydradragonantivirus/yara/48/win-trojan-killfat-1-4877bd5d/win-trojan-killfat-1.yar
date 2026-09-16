rule Win_Trojan_KillFat_1
{
strings:
	$a0 = { 52b80d00cd21b419cd2133d2e800008beb268b4e1603c9ba0100cd265a585d59c3 }


condition:
	$a0
}