rule _Armadillo_v4x_
{
	meta:
		description = "Armadillo v4.x"
	strings:
		$0 = {8B}
	condition:
		$0 at entrypoint
}