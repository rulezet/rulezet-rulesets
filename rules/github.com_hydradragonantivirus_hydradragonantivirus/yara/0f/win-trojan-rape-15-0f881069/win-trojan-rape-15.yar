rule Win_Trojan_Rape_15
{
strings:
	$a0 = { 4083e8038984e5018bd681c2e401b90300b440cd2133c9ba0000b80242cd21568bfe81c666 }


condition:
	$a0
}