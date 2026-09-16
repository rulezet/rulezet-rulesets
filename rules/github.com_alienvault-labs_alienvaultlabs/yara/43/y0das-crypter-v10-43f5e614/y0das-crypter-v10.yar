rule _y0das_Crypter_v10_
{
	meta:
		description = "y0da's Crypter v1.0"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED 8A 1C 40 ?? B9 9E ?? ?? ?? 8D BD 4C 23 40 ?? 8B F7}
	condition:
		$0 at entrypoint
}