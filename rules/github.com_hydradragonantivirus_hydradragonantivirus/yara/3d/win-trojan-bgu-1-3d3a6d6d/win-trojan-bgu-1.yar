rule Win_Trojan_BGU_1
{
strings:
	$a0 = { 40ba0500b90f05e809feb8004233c98bd1e8fffdb440ba1a05b91800e8f4fd8b0e16058b161805 }


condition:
	$a0
}