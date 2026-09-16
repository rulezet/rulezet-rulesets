rule _Guardant_Stealth_aka_Novex_Dongle_
{
	meta:
		description = "Guardant Stealth aka Novex Dongle"
	strings:
		$0 = {50 53 51 52 57 56 8B 75 1C 8B 3E 8B 5D 08 8A FB 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF}
	condition:
		$0 at entrypoint
}