rule Win_Spyware_54878_1
{
strings:
	$a0 = { 908bff9090b86578650033dbc745b033363054c745b47261792e8945b8895dbc8bff90 }


condition:
	$a0
}