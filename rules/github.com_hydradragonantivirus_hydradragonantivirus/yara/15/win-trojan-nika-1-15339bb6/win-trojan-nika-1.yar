rule Win_Trojan_Nika_1
{
strings:
	$a0 = { 3603cd21b44ebafe01cd2172ecbe5403bfcc02b90c00f3a4becc02bfa602b90c00f3a4fcbfa602b02eb90900f2 }


condition:
	$a0
}