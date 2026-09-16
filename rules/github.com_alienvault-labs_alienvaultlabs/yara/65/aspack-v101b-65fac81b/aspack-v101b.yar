rule _ASPack_v101b_
{
	meta:
		description = "ASPack v1.01b"
	strings:
		$0 = {60 E8 5D 81 ED 3E D9 43 B8 38 03 C5 2B 85 0B DE 43 89 85 17 DE 43 80 BD 01 DE 43 75 15 FE 85 01 DE 43 E8 1D E8 79 02 E8 12 03 8B}
	condition:
		$0 at entrypoint
}