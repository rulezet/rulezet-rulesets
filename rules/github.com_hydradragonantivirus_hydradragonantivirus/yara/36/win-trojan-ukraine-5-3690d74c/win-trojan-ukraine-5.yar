rule Win_Trojan_Ukraine_5
{
strings:
	$a0 = { 5083c04180f0ca83c0c1d1c8d0c08bec82e8bbd1c029c283c0d631c280c06b81f00d99fa01c231c2d0c882c0ac81e8 }


condition:
	$a0
}