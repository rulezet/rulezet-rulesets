rule Win_Trojan_Vienna_22
{
strings:
	$a0 = { 40fec6b90b00cd21ff0cb8024233c933d2cd21b4408d966efeb99d01cd21b4408d564759cd21b8 }


condition:
	$a0
}