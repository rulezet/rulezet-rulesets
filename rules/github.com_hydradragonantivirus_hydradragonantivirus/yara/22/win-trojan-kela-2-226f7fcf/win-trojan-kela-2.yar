rule Win_Trojan_Kela_2
{
strings:
	$a0 = { 40ba0001b99304e83202b8004233c933d2e828020e1fb440ba6705b90600e81b02b801572e8b0e }


condition:
	$a0
}