rule Win_Trojan_Turbo_3
{
strings:
	$a0 = { e92ea2bd02b0052ea2c002b90400babd028cc88ed8b440 }


condition:
	$a0
}