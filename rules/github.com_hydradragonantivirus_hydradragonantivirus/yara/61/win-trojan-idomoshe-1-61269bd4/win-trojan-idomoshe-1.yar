rule Win_Trojan_IdoMoshe_1
{
strings:
	$a0 = { c5009a000050005589e5833ec40307750ec706bc030010c706be0300b0eb0cc706bc030010c706be0300b89a32 }


condition:
	$a0
}