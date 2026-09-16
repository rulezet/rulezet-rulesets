rule Win_Trojan_Small_3296
{
strings:
	$a0 = { 73b16ad6fe215f5cde5d5b0a43b2f04aa4d4fde855a513fd110b6724daedc2b9b26a66233f2637623c8c9f49788cd6b48f49cb66336b3d673a6036562f15 }


condition:
	$a0
}