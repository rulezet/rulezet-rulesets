rule Win_Trojan_Andromeda_10
{
strings:
	$a0 = { 7503e9f80080fc30750981fefdcd7503bfcdabfb }


condition:
	$a0
}