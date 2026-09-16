rule Win_Trojan_Agent_35790
{
strings:
	$a0 = { 68fbcf85bae899600000894c242468385eacb0ff34249c8d642430e9292a0000 }


condition:
	$a0
}