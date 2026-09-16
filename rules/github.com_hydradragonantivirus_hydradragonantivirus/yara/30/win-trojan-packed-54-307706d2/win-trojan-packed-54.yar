rule Win_Trojan_Packed_54
{
strings:
	$a0 = { 33f6b882204100bbac214100fe00403bc375f94681fec13c030075e633f6cfcfcff7b3407f3fcaaf4bc0053f3f7f3ffe }


condition:
	$a0
}