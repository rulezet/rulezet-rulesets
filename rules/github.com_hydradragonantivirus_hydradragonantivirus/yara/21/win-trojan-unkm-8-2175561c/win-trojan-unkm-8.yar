rule Win_Trojan_Unkm_8
{
strings:
	$a0 = { b8000081ed06018db60e03bf000157a5a4b4098d966101cd21eb1790b4098d969c01cd21b90800be0000c682d10100 }


condition:
	$a0
}