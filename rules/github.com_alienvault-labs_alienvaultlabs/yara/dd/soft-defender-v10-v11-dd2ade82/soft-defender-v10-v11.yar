rule _Soft_Defender_v10__v11_
{
	meta:
		description = "Soft Defender v1.0 - v1.1"
	strings:
		$0 = {55 8B EC 83 EC 53 56 57 E9}
	condition:
		$0 at entrypoint
}