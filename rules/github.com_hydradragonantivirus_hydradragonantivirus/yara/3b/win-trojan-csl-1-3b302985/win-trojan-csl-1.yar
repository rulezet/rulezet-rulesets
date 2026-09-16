rule Win_Trojan_Csl_1
{
strings:
	$a0 = { f6368e5c2cb9ff7f412bedb8002383c601833c0075f5adadbf8d03b90002d1c9f3a40e1fb8f7dff7d0ba2d00c1ca }


condition:
	$a0
}