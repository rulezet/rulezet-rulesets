rule Win_Trojan_Vico_1
{
strings:
	$a0 = { 0300a33e00050301a30200b44033d252b9c903cd21e83d00b440ba0b01b91f00cd21e83000 }


condition:
	$a0
}