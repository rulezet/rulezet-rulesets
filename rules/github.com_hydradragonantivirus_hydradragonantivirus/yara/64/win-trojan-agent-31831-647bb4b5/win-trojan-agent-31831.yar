rule Win_Trojan_Agent_31831
{
strings:
	$a0 = { ff75e0ff150038a021f605db37a021020f8577f3ffffe986000000 }


condition:
	$a0
}