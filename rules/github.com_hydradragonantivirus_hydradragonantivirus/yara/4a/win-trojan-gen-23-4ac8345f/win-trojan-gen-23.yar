rule Win_Trojan_Gen_23
{
strings:
	$a0 = { 408d967604b90300cd21a1960024e00c0ca39600e848000633c08ec0faa1b20026a39000a1b400 }


condition:
	$a0
}