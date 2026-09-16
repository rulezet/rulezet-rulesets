rule Win_Trojan_Malaise_1
{
strings:
	$a0 = { 9c3d004b74103d12ef7505b834129dcf9d2eff2eb6012e8c }


condition:
	$a0
}