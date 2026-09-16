rule Win_Trojan_Ermua_2
{
strings:
	$a0 = { 5848508f47036bc040500787064e00508f06617d }


condition:
	$a0
}