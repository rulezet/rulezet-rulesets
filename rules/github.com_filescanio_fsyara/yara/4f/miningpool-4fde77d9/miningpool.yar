rule MiningPool : hardened
{
	meta:
		description = "Contains references to mining pools"
		author = "Ivan Kwiatkowski (@JusticeRage), based on an idea from @__Emilien__"

	strings:
		$stratum = /stratum\+tcp:\/\/[A-Za-z0-9-.:]*/

	condition:
		$stratum
}