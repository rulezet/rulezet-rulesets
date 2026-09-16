rule Win_Spyware_59736_2
{
strings:
	$a0 = { 558bec81ec1c0600005356 }

	$a1 = { 2f66656e2f30332f706f73742e617370 }

	$a2 = { 736830373030362e696e69 }


condition:
	$a0 and $a1 and $a2
}