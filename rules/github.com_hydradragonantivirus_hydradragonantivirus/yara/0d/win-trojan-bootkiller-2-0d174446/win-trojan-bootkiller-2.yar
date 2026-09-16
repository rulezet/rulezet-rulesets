rule Win_Trojan_BootKiller_2
{
strings:
	$a0 = { 05b202b600b500b101b00fcd13b400cd21ff7513b8190050b8f3253400eb58bb5583c404e9c600 }


condition:
	$a0
}