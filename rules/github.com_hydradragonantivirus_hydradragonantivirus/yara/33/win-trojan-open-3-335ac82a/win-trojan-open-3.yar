rule Win_Trojan_Open_3
{
strings:
	$a0 = { 03000e1fb8ac4bcd213d4bac74668cc0488ed8803e00005a755a830603009c830612009ca112000e1f0633db8e }


condition:
	$a0
}