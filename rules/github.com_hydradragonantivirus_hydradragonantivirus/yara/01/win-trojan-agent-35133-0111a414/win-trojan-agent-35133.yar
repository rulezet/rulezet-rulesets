rule Win_Trojan_Agent_35133
{
strings:
	$a0 = { 1dfdb9d53ab460d0c77171c73306f6a99ad7bd84a0e645028b4165223ddf3ea9f2beefb6e95c26026942e3a3e2cf92bd69304ca6d54629c3465aadc4e7627df662eead3d46adb2867a08ab0579b5bebd }


condition:
	$a0
}