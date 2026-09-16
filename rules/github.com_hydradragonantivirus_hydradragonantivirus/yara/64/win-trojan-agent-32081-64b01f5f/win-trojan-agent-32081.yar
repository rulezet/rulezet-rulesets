rule Win_Trojan_Agent_32081
{
strings:
	$a0 = { 8b4d08e8c2030000ff2564a52b2a84c0744de9a5feffffff35b4a42b2aff75e053ff15c4ea2b2a85c0ff25d0a42b2a }


condition:
	$a0
}