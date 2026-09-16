rule Win_Trojan_Rusher_1
{
strings:
	$a0 = { 720003c350b8ffffcba113042d0200a31304b106d3e02dc0078ec0be007c8bfec606bc0369a3be }


condition:
	$a0
}