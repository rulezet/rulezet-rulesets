rule Win_Trojan_Tequila_3
{
strings:
	$a0 = { 38fe8edbbe080084cbbb680985c039c1b9600939e889c78a17fc3014 }


condition:
	$a0
}