rule Win_Adware_Softonic_1
{
strings:
	$a0 = { 415657696e4150494057696e546f6f6c73404c696240536f66746f6e69634040 }


condition:
	$a0
}