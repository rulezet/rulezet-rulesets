rule Win_Trojan_Small_3799
{
strings:
	$a0 = { a39e4068d8ae0ef7639dd1e574debbdd62b40f9ea39e45d262fe19e82c6212e4ee1ae099e89d30b0ee12e09deea446d99b9a4156d8b3f655dbaf0ce44baebb8d6321c285bdf748d46789bec023fe }


condition:
	$a0
}