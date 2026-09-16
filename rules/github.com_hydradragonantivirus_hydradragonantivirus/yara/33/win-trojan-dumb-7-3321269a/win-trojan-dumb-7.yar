rule Win_Trojan_Dumb_7
{
strings:
	$a0 = { bf00015781ed06018db60c01a5a48d96e801e8e5ffb44e8d96060133c92e888e12022e80be12020377cdcd2172c9b8 }


condition:
	$a0
}