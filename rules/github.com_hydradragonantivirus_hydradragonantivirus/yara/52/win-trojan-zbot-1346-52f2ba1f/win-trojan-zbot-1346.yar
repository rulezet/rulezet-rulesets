rule Win_Trojan_Zbot_1346
{
strings:
	$a0 = { 8b95a0f6ffff33c08a8415a7f6ffff83f00233858cf6ffff8b8da0f6ffff88840da7f6ffff[0-20]410f95c0ff75203bc68d8d6cfdffff59e815ffffff[0-75]8b95a0f6ffff33c08a8415a7f6ffff83f0028b8da0f6ffff88840da7f6ffff }


condition:
	$a0
}