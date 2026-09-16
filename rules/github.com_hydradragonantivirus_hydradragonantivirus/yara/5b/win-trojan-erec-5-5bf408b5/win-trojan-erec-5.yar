rule Win_Trojan_Erec_5
{
strings:
	$a0 = { 21ba0000b9d102b440cd213dd102751bb90000ba0000b80042cd21bad102b91c00b440cd217204 }


condition:
	$a0
}