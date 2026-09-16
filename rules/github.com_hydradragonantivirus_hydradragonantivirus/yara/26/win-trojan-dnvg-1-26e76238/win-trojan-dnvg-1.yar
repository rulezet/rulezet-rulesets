rule Win_Trojan_DNVG_1
{
strings:
	$a0 = { 746f72202f20534757575d9a000085005589e550e4210c03e62158e81efae82fff50e42124fc }


condition:
	$a0
}