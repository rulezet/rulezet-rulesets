rule Win_Trojan_Sebal_1
{
strings:
	$a0 = { 5053bb1000f7f32bda8bcb5bb440ba7903cd2172515803c12d0300a3300305d8032ea30101b440 }


condition:
	$a0
}