rule Win_Trojan_VGEN_252
{
strings:
	$a0 = { 213c02740d77168d167007b409cd21e9aa008d16a307b409cd21eb4090a12c008ec033ffb9ff7f32c0f2ae2680 }


condition:
	$a0
}