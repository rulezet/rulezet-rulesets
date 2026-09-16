rule Win_Trojan_Peed_115
{
strings:
	$a0 = { 0544320f0087ca0f8588000000ba0400000087d181c42314000081ec1f140000 }


condition:
	$a0
}