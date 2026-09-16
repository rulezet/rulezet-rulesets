rule Win_Trojan_VComm_2
{
strings:
	$a0 = { b440cd21e83e00a19702a33202a19902a330021e }


condition:
	$a0
}