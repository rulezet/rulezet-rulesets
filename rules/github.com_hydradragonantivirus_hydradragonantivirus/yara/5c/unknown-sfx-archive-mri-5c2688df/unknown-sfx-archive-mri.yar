import "pe"
rule _Unknown_SFX_Archive_MRI_
{
	meta:
		description = "Unknown SFX Archive (MRI)"
	strings:
		$0 = {4D 52 49}
	condition:
		$0 at pe.entry_point
}