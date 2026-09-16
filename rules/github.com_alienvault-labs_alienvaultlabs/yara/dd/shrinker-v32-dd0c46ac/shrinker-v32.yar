rule _Shrinker_v32_
{
	meta:
		description = "Shrinker v3.2"
	strings:
		$0 = {83 3D ?? ?? 55 8B EC 56 57 75 65 68 ?? 01 ?? ??}
	condition:
		$0 at entrypoint
}