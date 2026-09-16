rule Win_Trojan_VGEN_420
{
strings:
	$a0 = { ed0301b9eb09b805feebfc80c43bebf42ec686dc0100b82435cd21b82425bad201cd218d96d601b44ee80e00cd20 }


condition:
	$a0
}