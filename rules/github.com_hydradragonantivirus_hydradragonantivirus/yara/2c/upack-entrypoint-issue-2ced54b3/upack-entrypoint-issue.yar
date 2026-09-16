import "pe"
rule Upack_entrypoint_issue
{
	meta:
		author="_pusher_"
	strings:
		$right = { BE B0 11 40 00 }
		$wrong = { 0B 01 4C 6F 61 64 4C }
	condition:
		$right at pe.entry_point or 
		$wrong at pe.entry_point
}