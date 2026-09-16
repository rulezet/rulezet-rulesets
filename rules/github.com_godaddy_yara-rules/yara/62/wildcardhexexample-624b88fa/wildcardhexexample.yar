rule WildcardHexExample {
	strings:
				$hex_string1 = { 012345????ABCDEF }
		$hex_string2 = { 012345????abcdef }
		$hex_string3 = { 01 23 45 ?? ?? ab cd ef }
	
	condition:
				$hex_string1 or $hex_string2 or $hex_string3
}