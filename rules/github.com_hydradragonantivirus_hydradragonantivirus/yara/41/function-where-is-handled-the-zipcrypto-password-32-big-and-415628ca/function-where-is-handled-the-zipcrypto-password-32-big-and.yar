rule function_where_is_handled_the_ZipCrypto_password__32_big_AND_
{
strings:
	$a0 = { 12345678[0-20]23456789[0-20]34567890 }

condition:
	$a0
}