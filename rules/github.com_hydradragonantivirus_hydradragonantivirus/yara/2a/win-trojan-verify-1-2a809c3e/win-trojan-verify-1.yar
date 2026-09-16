rule Win_Trojan_Verify_1
{
strings:
	$a0 = { d0bc007c501ffba113044848a31304b106d3e08ec08b0e787c8b167a7c33dbbf0500b80102cd13 }


condition:
	$a0
}