rule Win_Trojan_Bomb_1
{
strings:
	$a0 = { 03008be88cc88ed88ec08bf5bf0001b9b30681e9ff0083c120fcf3a4bf2801ffe790e8c7018cc88ed08ec0bb }


condition:
	$a0
}