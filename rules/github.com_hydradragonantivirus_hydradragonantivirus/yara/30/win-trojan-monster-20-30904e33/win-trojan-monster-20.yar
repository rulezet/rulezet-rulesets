rule Win_Trojan_Monster_20
{
strings:
	$a0 = { 02bedc2c8034cd46e2fa25cdcd934e23ce250dcc00ed0b89dc3326cd0b89dccd2547cc4649fbcf6ecdcc4749f5cf }


condition:
	$a0
}