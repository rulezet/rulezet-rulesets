rule _UPX_v0896__v102__v105__v122_DLL_
{
	meta:
		description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL"
	strings:
		$0 = {8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB}
	condition:
		$0 at entrypoint
}