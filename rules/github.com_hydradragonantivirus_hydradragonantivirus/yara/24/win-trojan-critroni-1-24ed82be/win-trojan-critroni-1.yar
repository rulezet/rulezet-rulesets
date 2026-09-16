rule Win_Trojan_Critroni_1
{
strings:
	$a0 = { 8bf85985ff75273905e4614c00761f56ff15941041008d86e80300003b05e4614c00760383c8ff8bf083f8ff75ca8bc75f5e }


condition:
	$a0
}