rule WarBird
{
	meta:
		author="Nukem9"
		date = "2016-08"
		description="Match the PEB.Ldr assembly for warbird function resolution"
		link = "https://thisissecurity.net/2014/10/15/warbird-operation/"
	strings:
		$a = { 64 A1 30 00 00 00 2B CA D1 F9 8B 40 0C 83 C0 0C }
	condition:
		$a
}