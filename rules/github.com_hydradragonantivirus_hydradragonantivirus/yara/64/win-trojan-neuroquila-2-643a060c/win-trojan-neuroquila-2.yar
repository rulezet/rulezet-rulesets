rule Win_Trojan_Neuroquila_2
{
strings:
	$a0 = { 8d06????c7c1????b4b80eb09c1ffcbe2d00b8c745f8110c8bc38db40200b8????2bc6f5b8????7704fde9e8ff }


condition:
	$a0
}