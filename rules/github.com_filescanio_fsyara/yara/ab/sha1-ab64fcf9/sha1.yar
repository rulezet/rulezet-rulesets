rule SHA1 : hardened
{
	meta:
		description = "Uses constants related to SHA1"
		author = "Ivan Kwiatkowski (@JusticeRage)"

	strings:
		$sha1_f1 = { 99 79 82 5A }
		$sha1_f2 = { a1 eb d9 6e }
		$sha1_f3 = { dc bc 1b 8f }
		$sha1_f4 = { d6 c1 62 ca }

	condition:
		all of ( $sha1_f* )
}