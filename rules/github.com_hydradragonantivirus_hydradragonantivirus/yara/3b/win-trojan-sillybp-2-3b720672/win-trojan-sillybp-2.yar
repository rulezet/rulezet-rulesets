rule Win_Trojan_SillyBP_2
{
strings:
	$a0 = { 4c00a3c07ca14e00a3c27ca1130448a31304b106d3e08ec0a33d7ca34e00c7064c009800be007c }


condition:
	$a0
}