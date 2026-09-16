rule Win_Trojan_Lyby_1
{
strings:
	$a0 = { 05100050b8110050cbb8cdabcd213dbadc750a5916161f07b8bbbbcd21e80500e82b00ebee8cc0488ed8b84d00 }


condition:
	$a0
}