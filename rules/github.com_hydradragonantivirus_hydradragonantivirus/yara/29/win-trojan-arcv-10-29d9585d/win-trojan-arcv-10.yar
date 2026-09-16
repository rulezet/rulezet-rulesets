rule Win_Trojan_ARCV_10
{
strings:
	$a0 = { 020e1f8c0674038c167603892678038cc883c01033db4b8be38ed0e80d02a103038cc383c31003c3a3 }


condition:
	$a0
}