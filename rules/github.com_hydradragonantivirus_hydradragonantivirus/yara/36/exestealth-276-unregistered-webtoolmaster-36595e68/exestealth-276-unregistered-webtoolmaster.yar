rule _EXEStealth_276_Unregistered__WebtoolMaster_
{
	meta:
		description = "EXEStealth 2.76 Unregistered -> WebtoolMaster"
	strings:
		$0 = {EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20}
	condition:
		$0
}