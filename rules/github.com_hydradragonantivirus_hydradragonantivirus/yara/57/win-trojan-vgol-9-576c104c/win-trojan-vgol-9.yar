rule Win_Trojan_VGOL_9
{
strings:
	$a0 = { e8040e5b01c353681000cbb8d0f3bb9f0c3d32007f06050b0043ebf52d0a004b75efffe00e1f803e4003fe75162e }


condition:
	$a0
}