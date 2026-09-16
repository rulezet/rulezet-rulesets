rule Win_Trojan_VB_107_12
{
strings:
	$a0 = { 506c7567d93116fe696e5f4d46756e233bb7a8a007ff071bc290dd074b5d173416 }


condition:
	$a0
}