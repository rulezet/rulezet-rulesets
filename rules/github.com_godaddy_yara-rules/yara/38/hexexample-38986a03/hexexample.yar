rule HexExample {
	strings:
				$hex_string1 = { 0123456789ABCDEF }
		$hex_string2 = { 0123456789abcdef }
		$hex_string3 = { 01 23 45 67 89 ab cd ef }
	
	condition:
				$hex_string1 or $hex_string2 or $hex_string3
}