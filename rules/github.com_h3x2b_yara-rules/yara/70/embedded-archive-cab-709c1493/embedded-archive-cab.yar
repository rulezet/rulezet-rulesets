rule embedded_archive_cab : info embedded archive cab windows
{
	meta:
				description = "Detect CAB archive"

	strings:
		$mscf_h3xstring = { 4D 53 43 46 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 }

	condition:
                		$mscf_h3xstring
}