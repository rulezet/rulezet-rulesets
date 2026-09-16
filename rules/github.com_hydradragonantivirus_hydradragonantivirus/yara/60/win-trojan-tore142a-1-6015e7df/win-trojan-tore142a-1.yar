rule Win_Trojan_TORE142A_1
{
strings:
	$a0 = { 40b99505ba0000e84700582d03002ea39005e8f900e8fc00b440b90300ba8f05e82e00268b4511 }


condition:
	$a0
}