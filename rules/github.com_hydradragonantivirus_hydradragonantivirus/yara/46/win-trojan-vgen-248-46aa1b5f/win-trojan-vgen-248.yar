rule Win_Trojan_VGEN_248
{
strings:
	$a0 = { 30cd213c02740d77168d165a07b409cd21e9f6008d168d07b409cd21eb4090a12c008ec033ffb9ff7f32c0f2ae2680 }


condition:
	$a0
}