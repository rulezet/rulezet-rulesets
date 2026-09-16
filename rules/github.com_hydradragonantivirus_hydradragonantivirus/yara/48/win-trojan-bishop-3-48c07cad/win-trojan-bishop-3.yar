rule Win_Trojan_Bishop_3
{
strings:
	$a0 = { 20464f4f4c202121210a2f43203239612e6578659a00004c029a0d00ea015589e5b80003 }


condition:
	$a0
}