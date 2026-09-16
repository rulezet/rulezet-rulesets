rule xlok
{
	meta:
		author = "PEiD"
		description = "XtreamLok -> XtreamLok.com"
		group = "167"
		function = "0"
	strings:
		$a0 = { 90 90 90 EB 29 }
	condition:
		$a0
}