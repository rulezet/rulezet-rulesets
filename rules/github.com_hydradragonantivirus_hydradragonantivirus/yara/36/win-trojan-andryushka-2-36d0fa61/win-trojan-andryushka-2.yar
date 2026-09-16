rule Win_Trojan_Andryushka_2
{
strings:
	$a0 = { 583c3c0ee242381ec2b10b778b0ee2b101ab6d23c524e5e2e3e3e3c563dde3e3b976b02603060300 }


condition:
	$a0
}