rule _MinGW_v32x__mainCRTStartup_
{
	meta:
		description = "MinGW v3.2.x (_mainCRTStartup)"
	strings:
		$0 = {E8 FF FF E8 FF}
	condition:
		$0 at entrypoint
}