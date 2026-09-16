import "pe"
rule _PCrypt_350_COM_
{
	meta:
		description = "PCrypt 3.50 [COM]"
	strings:
		$0 = {50 43 52 59 50 54 E9}
	condition:
		$0 at pe.entry_point
}