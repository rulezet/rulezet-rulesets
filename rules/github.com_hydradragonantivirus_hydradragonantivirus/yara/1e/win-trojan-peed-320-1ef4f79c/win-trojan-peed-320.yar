rule Win_Trojan_Peed_320
{
strings:
	$a0 = { e85a00000052ad05????????eb2ae2f6c3ab50525183c8ff4005998a400029db8b0829c05353ffd14093595a5801df83 }


condition:
	$a0
}