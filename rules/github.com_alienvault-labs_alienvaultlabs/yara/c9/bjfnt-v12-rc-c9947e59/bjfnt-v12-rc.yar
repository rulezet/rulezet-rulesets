rule _BJFnt_v12_RC_
{
	meta:
		description = ".BJFnt v1.2 RC"
	strings:
		$0 = {EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20}
	condition:
		$0 at entrypoint
}