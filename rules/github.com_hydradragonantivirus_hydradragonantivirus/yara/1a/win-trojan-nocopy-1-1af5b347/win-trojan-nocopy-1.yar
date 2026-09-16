rule Win_Trojan_NoCopy_1
{
strings:
	$a0 = { c7050002b91b00268c4d028cc88ed88ec0b81b00be2102bf1b00b965022bce8bfefccdfbe2fc }


condition:
	$a0
}