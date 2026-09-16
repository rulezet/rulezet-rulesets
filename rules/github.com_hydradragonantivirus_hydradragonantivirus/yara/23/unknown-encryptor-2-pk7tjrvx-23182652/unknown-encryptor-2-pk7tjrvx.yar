import "pe"
rule _Unknown_encryptor_2__PK7Tjrvx_
{
	meta:
		description = "Unknown encryptor (2) - PK7Tjrvx"
	strings:
		$0 = {06 B4 52 CD 21 07 E8 ?? ?? B4 62 CD 21 E8}
	condition:
		$0 at pe.entry_point
}