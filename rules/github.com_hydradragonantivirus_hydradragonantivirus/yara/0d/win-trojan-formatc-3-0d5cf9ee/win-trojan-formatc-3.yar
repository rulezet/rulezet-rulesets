rule Win_Trojan_Formatc_3
{
strings:
	$a0 = { 676f795d3d2d20406563686f2e20406563686f2e206563686f206f7c666f726d617420633a }


condition:
	$a0
}