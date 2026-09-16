rule Win_Dropper_Agent_33672
{
strings:
	$a0 = { feff8b4dfc8b530c8b4304e84ba0ffff33c05a595964891068369241008d45fce8eadafeffc3e90cbafeffebf05e5b595dc390558bec83c4f853565733c9894df88bda8bf033c05568e292410064ff30 }


condition:
	$a0
}