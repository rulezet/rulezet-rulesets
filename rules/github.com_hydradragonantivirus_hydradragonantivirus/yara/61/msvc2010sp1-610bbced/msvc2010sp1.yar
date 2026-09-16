import "pe"
rule MSVC2010sp1
{
	meta:
		author="_pusher_"
		date = "2016-08"
		linker = "10.10"
	condition:
		pe.rich_signature.version(30716) and (pe.linker_version.major == 10) and (pe.linker_version.minor == 10 )
}