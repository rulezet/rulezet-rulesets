rule Win_Trojan_Em_2
{
strings:
	$a0 = { c88cd38bd48ed0bcfeff53522d050050bb0001538cda8c }


condition:
	$a0
}