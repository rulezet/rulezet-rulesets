rule Win_Trojan_Agent_34174
{
strings:
	$a0 = { 9b9b60e803000000eb03ebc3eb61eb5ccc }


condition:
	$a0
}