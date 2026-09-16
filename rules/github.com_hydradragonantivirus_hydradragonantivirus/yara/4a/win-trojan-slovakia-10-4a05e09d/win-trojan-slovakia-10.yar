rule Win_Trojan_Slovakia_10
{
strings:
	$a0 = { df5e5ab85dcf81d15657220533d281c27206be7dcc0284c1264081c7bf4d81df5a594f81f632cc026675bfcd0640 }


condition:
	$a0
}