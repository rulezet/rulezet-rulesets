rule Win_Trojan_VGEN_724
{
strings:
	$a0 = { cd213c02740d77168d166007b409cd21eb4a908d169307b409cd21eb44902ea12c008ec033ffb9ff7f32c0f2ae26 }


condition:
	$a0
}