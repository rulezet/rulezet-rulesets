rule Win_Trojan_Small_4450
{
strings:
	$a0 = { 6a00810424007640008d1c240f6e??0f }


condition:
	$a0
}