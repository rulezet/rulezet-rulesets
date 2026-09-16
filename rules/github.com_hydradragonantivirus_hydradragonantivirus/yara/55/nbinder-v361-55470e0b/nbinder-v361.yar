rule _nBinder_v361_
{
	meta:
		description = "nBinder v3.6.1"
	strings:
		$0 = {6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C 00 5C 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C}
	condition:
		$0
}