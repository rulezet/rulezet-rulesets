rule Win_Trojan_KeyPress_2
{
strings:
	$a0 = { 40b90200ba9305cd21b440b90200ba6f05cd21b440b90c00ba8705cd21c3b440b91800ba5705cd }


condition:
	$a0
}