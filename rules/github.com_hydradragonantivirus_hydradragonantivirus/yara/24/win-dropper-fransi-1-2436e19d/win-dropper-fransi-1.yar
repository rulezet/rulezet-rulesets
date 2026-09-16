rule Win_Dropper_Fransi_1
{
strings:
	$a0 = { 57696e646f7773[9]6235525a3638[56]54656d70[10]6235575a3838 }


condition:
	$a0
}