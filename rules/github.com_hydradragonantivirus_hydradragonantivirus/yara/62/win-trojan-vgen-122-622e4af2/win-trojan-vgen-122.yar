rule Win_Trojan_VGEN_122
{
strings:
	$a0 = { c601b96400be8000bfd1f090fcf3a4b44e681801c358b92000babc01cd217270813e9a00c800722f813e9a0048ee }


condition:
	$a0
}