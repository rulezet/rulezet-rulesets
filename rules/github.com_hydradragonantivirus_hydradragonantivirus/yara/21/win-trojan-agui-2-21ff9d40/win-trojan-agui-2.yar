rule Win_Trojan_Agui_2
{
strings:
	$a0 = { 5c6f656170692e766273 }

	$a1 = { 6d6964286c69676e652c692c322929 }

	$a2 = { 72756e207878202620225c796964616e692e6a7067 }


condition:
	$a0 and $a1 and $a2
}