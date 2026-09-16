rule Win_Trojan_Agent_35779
{
strings:
	$a0 = { 558becb9d40400006a006a004975f951535657b838ee1413e86f67ffff33c055 }


condition:
	$a0
}