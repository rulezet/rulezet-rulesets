rule Win_Trojan_Tranquilo_1
{
strings:
	$a0 = { 02c6068902e9a38a02c6068c0240b80042b90000ba0000cd21b440b90400ba8902cd21b80242 }


condition:
	$a0
}