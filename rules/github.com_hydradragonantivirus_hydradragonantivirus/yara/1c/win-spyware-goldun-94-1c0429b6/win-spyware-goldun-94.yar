rule Win_Spyware_Goldun_94
{
strings:
	$a0 = { 796d6fffa1f8616e746563216469737061741e2e6d6307c87ff661666565136f776e }


condition:
	$a0
}