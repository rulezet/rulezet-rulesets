rule UnicodeExample {
strings:
		$unicode_string = "hello" wide

condition:
	$unicode_string
}