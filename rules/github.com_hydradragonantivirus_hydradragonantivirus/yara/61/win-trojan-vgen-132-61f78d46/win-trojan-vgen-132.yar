rule Win_Trojan_VGEN_132
{
strings:
	$a0 = { 5e81ee03015681c6f40189f783c704b90400f2a45eb42ccd2180fd047f0eb4098d94bc01cd21b400cd16cd19b44e8d }


condition:
	$a0
}