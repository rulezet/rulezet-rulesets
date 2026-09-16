rule Win_Trojan_Kitana_19
{
strings:
	$a0 = { 5e9d752148cd13b80102ba80008ac88bd8cd13803f85740cb801034150cd135887f3e2f8c30e }


condition:
	$a0
}