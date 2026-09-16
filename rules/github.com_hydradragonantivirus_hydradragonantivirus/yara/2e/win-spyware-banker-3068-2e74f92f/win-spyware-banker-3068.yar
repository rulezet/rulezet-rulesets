rule Win_Spyware_Banker_3068
{
strings:
	$a0 = { 49a2644f282f85b18e3642170f122f3f836e27bc1694a580feb7ae73425f75dfde44771899e13db1174674f79eea0a5bea0a1de467f7e403bac07ba9768f }


condition:
	$a0
}