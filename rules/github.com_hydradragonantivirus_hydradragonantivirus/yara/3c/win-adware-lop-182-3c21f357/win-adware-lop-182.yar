rule Win_Adware_Lop_182
{
strings:
	$a0 = { e3f467777b081c4f64b172010a87f6403b3c60d19660c915285c66d06b92f40f144a72cb104ad9802b252e4ce88250afee3f4fea05540eac39b75fca }


condition:
	$a0
}