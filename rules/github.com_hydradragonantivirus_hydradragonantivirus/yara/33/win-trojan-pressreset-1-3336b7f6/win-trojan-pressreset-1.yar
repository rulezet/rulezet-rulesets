rule Win_Trojan_PressReset_1
{
strings:
	$a0 = { 21b4408bd583c206b90300cd21b8024233d233c9cd21b440b95f028bd583ea23cd21b80157595a }


condition:
	$a0
}