rule ole_equation_editor : info ole equation_editor windows
{
	meta:
						description = "Detect embedded CLSID OLE of Equation Editor used in CVE-2017-11882"

	strings:
		$clsid_equation_editor = { 02 CE 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

	condition:
		$clsid_equation_editor
}