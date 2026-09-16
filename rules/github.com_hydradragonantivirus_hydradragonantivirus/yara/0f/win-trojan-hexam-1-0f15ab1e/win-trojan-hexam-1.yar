rule Win_Trojan_Hexam_1
{
strings:
	$a0 = { 81ed08018db62601e80200eb108b96c802b9a2018bfeac32c2aae2fac3b41aba64facd218db62d02bf0001b90300fc }


condition:
	$a0
}