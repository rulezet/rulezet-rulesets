rule Win_Trojan_IntendDruid_1
{
strings:
	$a0 = { b8eb02ebfcbaee01b80125cd21b003cd21baee01b80125cd21b001cd21b44732d2bef901cd21baef01b44ecd217303eb5c90be9e00ad3d434f7508eb4c90b8eb }


condition:
	$a0
}