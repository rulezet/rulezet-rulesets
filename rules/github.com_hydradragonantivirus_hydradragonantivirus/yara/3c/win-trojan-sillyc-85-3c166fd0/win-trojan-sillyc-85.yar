rule Win_Trojan_SillyC_85
{
strings:
	$a0 = { 1abac001cd21b44ebaba01b120cd21720ee878000ac0744fbac001b44febeeff362c000733c08bf88bc849f2ae2683 }


condition:
	$a0
}