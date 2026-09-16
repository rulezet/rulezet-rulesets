rule Win_Trojan_VGEN_260
{
strings:
	$a0 = { 2ea12c008ed88ec02ea33e1933ffb001b9e803fcf2ae478bd72e89163c19b8003dcd217303e943018bd88cc88ed88e }


condition:
	$a0
}