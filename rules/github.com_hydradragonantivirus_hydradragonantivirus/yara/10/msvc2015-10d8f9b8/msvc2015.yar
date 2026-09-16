import "pe"
rule MSVC2015
{
	meta:
		author = "_pusher_"
		date = "2016-08"
		linker = "14.00"
	condition:
		(pe.rich_signature.version(24123) or pe.rich_signature.version(23907) ) and pe.rich_signature.version(40116) and (pe.rich_signature.toolid(239) or pe.rich_signature.toolid(243) ) or
		pe.rich_signature.version(24123) and pe.rich_signature.version(30729) and pe.rich_signature.toolid(147) or
		pe.rich_signature.version(24123) and pe.rich_signature.toolid(255) and ((pe.linker_version.major == 14) and (pe.linker_version.minor == 0 ))
		
}