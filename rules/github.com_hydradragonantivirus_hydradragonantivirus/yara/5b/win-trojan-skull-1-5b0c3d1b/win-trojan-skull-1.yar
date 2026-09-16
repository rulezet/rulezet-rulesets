rule Win_Trojan_Skull_1
{
strings:
	$a0 = { 97029a0d000c025589e531c09acd0297029acc010c02b08f509a63020c02b02350b00c509a1f020c02bfe0291e }


condition:
	$a0
}