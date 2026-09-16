rule Win_Trojan_Crypt_310
{
strings:
	$a0 = { 6a2a58c34d616743725970743072 }


condition:
	$a0
}