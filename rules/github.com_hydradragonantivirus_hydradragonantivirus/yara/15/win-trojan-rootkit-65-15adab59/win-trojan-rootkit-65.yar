rule Win_Trojan_Rootkit_65
{
strings:
	$a0 = { 8bff558bec51515356576878150100e88a0000008d45f8c704244615010050ff }


condition:
	$a0
}