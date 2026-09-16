rule Win_Trojan_Buz_1
{
strings:
	$a0 = { 20cd1372ecbfa301b80720ab47b88020abb80303bb8101b90720ba8020cd1372f0bfb605b080 }


condition:
	$a0
}