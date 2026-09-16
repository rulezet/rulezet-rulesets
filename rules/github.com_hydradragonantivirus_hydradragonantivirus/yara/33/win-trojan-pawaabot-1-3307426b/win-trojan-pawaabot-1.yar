rule Win_Trojan_Pawaabot_1
{
strings:
	$a0 = { 3b0a3f9e9725a958ce7065af184f3b2ddc3a0209baadddd9fe6756657943735c57771aef7d3297250caa4104ca681ea49e2b0a76cf2f6c4857577f5d7b7c5116 }


condition:
	$a0
}