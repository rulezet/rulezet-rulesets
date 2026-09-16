rule Win_Trojan_VB_107_10
{
strings:
	$a0 = { 42b7c14f506c7567696e5f496053d2ff6e7465726e657446756e899807efff3fc8 }


condition:
	$a0
}