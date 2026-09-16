import "pe"
rule _Protection_Plus_vxx_
{
	meta:
		description = "Protection Plus vx.x"
	strings:
		$0 = {40 20 FF ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF}
	condition:
		$0 at pe.entry_point
}