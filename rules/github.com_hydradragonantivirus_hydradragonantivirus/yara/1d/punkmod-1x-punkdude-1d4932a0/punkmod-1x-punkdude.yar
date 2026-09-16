rule _PuNkMoD_1x__PuNkDuDe_
{
	meta:
		description = "PuNkMoD 1.x -> PuNkDuDe"
	strings:
		$0 = {94 B9 ?? ?? 00 00 BC ?? ?? ?? ?? 80 34 0C}
	condition:
		$0
}