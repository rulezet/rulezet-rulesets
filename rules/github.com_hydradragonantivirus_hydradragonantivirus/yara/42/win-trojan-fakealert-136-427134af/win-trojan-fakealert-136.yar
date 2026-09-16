rule Win_Trojan_Fakealert_136
{
strings:
	$a0 = { 2bd103c103c203ca33ca81f9e80000000f841e000000390d003745000f85060000002bc8 }


condition:
	$a0
}