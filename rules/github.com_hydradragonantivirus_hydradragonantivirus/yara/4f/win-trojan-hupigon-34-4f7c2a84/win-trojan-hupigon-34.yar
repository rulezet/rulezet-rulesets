rule Win_Trojan_Hupigon_34
{
strings:
	$a0 = { 803d5ee91413007434e8728bffffa9000000807428a158e91413e84d79ffff506a01a154e91413e84079ffff8bc8ba7cc71413b801000080e88fd9ffff }


condition:
	$a0
}