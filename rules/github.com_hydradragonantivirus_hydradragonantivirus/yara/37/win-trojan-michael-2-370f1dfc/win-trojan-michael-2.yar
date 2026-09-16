rule Win_Trojan_Michael_2
{
strings:
	$a0 = { c08ed88ed0bc007cfba113042d0300a31304b106d3e0a39b7d8ec0be007c33ffb90001fcf3a5 }


condition:
	$a0
}