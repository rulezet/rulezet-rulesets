rule Win_Trojan_Vienna_123
{
strings:
	$a0 = { 51b98603ba8908bf????8bef8a054d8a66002ae0886600e2f5 }


condition:
	$a0
}