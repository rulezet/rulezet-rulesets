import "pe"
rule MSVC2013
{
	meta:
		author = "mrexodia & _pusher_"
		date = "2016-08"
		linker = "12.00"
	condition:
		pe.rich_signature.version(21005) and ( pe.rich_signature.version(40629) or pe.rich_signature.version(31101) or pe.rich_signature.version(30723) or pe.rich_signature.version(41118) ) and (pe.rich_signature.toolid(221) or pe.rich_signature.toolid(224) ) or
		pe.rich_signature.version(31101) and pe.rich_signature.version(20806) and (pe.rich_signature.toolid(221) or pe.rich_signature.toolid(225)) or
		pe.rich_signature.version(20806) and pe.rich_signature.version(21005) and pe.rich_signature.toolid(224) or
						pe.rich_signature.version(65501) and pe.rich_signature.version(20806) and pe.rich_signature.toolid(224)
}