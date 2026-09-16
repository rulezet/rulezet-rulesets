rule Win_Trojan_Agent_31337
{
strings:
	$a0 = { 747908727669636520284e53532900714aad36b920baaebc42357a154debba6dd77eff002e1e072417e10f3e23ed0ac1aeeb1fcb19cf96e4140ff6bbce0b07dc1f4368616e }


condition:
	$a0
}