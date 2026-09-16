rule Win_Trojan_Agent_34134
{
strings:
	$a0 = { 33c9bae8da4400a1280c4500e8b7f8ffff84c0741eb901000000ba2cdb4400a1280c4500e8eff9ffffa1280c4500e801f8ffff }


condition:
	$a0
}