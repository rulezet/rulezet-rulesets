rule _UPX_p_ECLiPSE_layer_
{
	meta:
		description = "UPX + ECLiPSE layer"
	strings:
		$0 = {90 61 BE 8D BE 57 83 CD}
	condition:
		$0 at entrypoint
}