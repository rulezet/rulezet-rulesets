rule ZipMaster_ZipSFX
{
	meta:
		author="_pusher_"
		date = "2016-07"
	strings:
		$a0 = "SFXInflate" wide ascii nocase
		$a1 = "SFXStructs" wide ascii nocase
		$a2 = "SysInit" wide ascii nocase
		$a3 = "Windows" wide ascii nocase
	condition:
		all of them
}