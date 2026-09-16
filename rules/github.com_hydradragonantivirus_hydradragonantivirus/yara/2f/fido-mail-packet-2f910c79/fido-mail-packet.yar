import "pe"
rule _FIDO_mail_packet_
{
	meta:
		description = "FIDO mail packet"
	strings:
		$0 = {03 00 03 00 CD 07}
	condition:
		$0 at pe.entry_point
}