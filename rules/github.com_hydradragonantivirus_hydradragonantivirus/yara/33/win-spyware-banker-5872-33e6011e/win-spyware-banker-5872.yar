rule Win_Spyware_Banker_5872
{
strings:
	$a0 = { 948472cfc879ff0755cda7d2705a1af9cd3afbe6b2a05affdbb623f463ca29683e3dea966e47478c89912510b7f891b6c14cf3a363e5ab226068f22d506c04691f5eba84 }


condition:
	$a0
}