rule Win_Trojan_Abba_1
{
strings:
	$a0 = { b8b44bcd213d1c00743f8cd8488ed8bb0300832f408b07b941008ed9ff0f0e1f8cc303d88ec3 }


condition:
	$a0
}