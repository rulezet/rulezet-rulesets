import "pe"
rule MSVC2003
{
	meta:
		author="_pusher_"
		date = "2016-08"
		linker = "7.10"
	condition:												pe.rich_signature.version(4035) and pe.rich_signature.version(50727) and pe.rich_signature.toolid(100) or
		pe.rich_signature.version(3052) and pe.rich_signature.version(9210) and pe.rich_signature.toolid(95) or
		pe.rich_signature.version(6030) and pe.rich_signature.version(2179) and pe.rich_signature.toolid(100) or
		pe.rich_signature.version(3077) and pe.rich_signature.version(2179) and (pe.rich_signature.toolid(95) or pe.rich_signature.toolid(96) ) or
		pe.rich_signature.version(4035) and pe.rich_signature.version(4031) and pe.rich_signature.toolid(95)
}