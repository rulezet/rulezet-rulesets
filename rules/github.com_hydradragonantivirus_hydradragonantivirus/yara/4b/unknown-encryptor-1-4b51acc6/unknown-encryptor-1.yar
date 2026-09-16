import "pe"
rule _Unknown_encryptor_1_
{
	meta:
		description = "Unknown encryptor (1)"
	strings:
		$0 = {EB ?? 2E 90 ?? ?? 8C DB 8C CA 8E DA FA 8B EC BE ?? ?? BC ?? ?? BF}
	condition:
		$0 at pe.entry_point
}