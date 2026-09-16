rule Win_Trojan_Girl_2
{
strings:
	$a0 = { 7c50508ed8a113044848a31304b106d3e02dc0078ec0a36d7cbe007c8bfeb90001f3a5ea6f7c }


condition:
	$a0
}