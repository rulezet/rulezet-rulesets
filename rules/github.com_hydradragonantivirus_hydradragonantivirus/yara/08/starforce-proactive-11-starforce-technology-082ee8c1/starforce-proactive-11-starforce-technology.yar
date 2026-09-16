import "pe"
rule _StarForce_ProActive_11__StarForce_Technology_
{
	meta:
		description = "StarForce ProActive 1.1 -> StarForce Technology"
	strings:
		$0 = {68 ?? ?? ?? ?? FF 25 ?? ?? 57}
	condition:
		$0 at pe.entry_point
}