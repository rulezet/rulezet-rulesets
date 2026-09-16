rule Win_Trojan_VLAD_23
{
strings:
	$a0 = { 81ed06018db67f02010101a5a4c686cc0200b44732d28db68c02cd213e1a8d96cd02a703b44eb90700fe8e85028d }


condition:
	$a0
}