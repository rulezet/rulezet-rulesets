import "pe"
rule NSPack3x : LiuXingPing
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01 }

condition:
		$a0 at pe.entry_point
}