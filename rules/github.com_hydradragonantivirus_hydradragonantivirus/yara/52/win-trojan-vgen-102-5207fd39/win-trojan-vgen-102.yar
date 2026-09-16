rule Win_Trojan_VGEN_102
{
strings:
	$a0 = { 2a06b8024ab704cd2f47bb06007409e8a000f32ea4e8ab00571fc5577eb80325cd211f433179fc75fab40dcc53 }


condition:
	$a0
}