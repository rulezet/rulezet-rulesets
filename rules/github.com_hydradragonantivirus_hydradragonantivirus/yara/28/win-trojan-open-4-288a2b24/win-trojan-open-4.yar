rule Win_Trojan_Open_4
{
strings:
	$a0 = { 03000e1fb8ac4bcd213d4bac74688cc0488ed8803e00005a755c810603009cff810612009cffa112000e1f0633 }


condition:
	$a0
}