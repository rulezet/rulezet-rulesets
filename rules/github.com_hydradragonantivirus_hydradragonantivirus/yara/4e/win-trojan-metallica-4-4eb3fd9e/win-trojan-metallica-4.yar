rule Win_Trojan_Metallica_4
{
strings:
	$a0 = { 42cd217234ba0002b98f01b440cd21722833c933d2b80042cd21721dba7f03b90300b440cd21 }


condition:
	$a0
}