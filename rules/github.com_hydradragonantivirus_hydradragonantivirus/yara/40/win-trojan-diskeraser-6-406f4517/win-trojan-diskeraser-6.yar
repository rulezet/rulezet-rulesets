rule Win_Trojan_DiskEraser_6
{
strings:
	$a0 = { b80103b90100ba8000bb00388ec3bb0000cd13cd19cd21 }


condition:
	$a0
}