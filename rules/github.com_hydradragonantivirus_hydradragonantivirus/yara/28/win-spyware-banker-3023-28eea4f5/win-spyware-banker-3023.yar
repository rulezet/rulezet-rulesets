rule Win_Spyware_Banker_3023
{
strings:
	$a0 = { 0963ce68f671cdc4a5c8004d25d62f58c16b45f22ce6e91d596c23c0f795e3d944630115845340a97798d4e1d80032cb }


condition:
	$a0
}