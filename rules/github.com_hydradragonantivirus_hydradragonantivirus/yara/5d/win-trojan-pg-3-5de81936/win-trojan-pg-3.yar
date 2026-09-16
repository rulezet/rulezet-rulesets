rule Win_Trojan_PG_3
{
strings:
	$a0 = { cd131fc4064c00c7064c00f1008c0e4e000e1fa37c018c067e01ea007c0000b80103eb03b80102 }


condition:
	$a0
}