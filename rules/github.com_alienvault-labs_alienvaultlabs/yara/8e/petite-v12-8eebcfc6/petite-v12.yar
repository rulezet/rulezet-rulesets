rule _PEtite_v12_
{
	meta:
		description = "PEtite v1.2"
	strings:
		$0 = {66 9C 60 50 8D 88 F0 8D 90 04 16 8B DC 8B E1 68 53 50 80 04 24 08 50 80 04 24}
	condition:
		$0 at entrypoint
}