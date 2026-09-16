rule Win_Trojan_Mini_5
{
strings:
	$a0 = { 023dba9e00cd2193b43f54598d12cd21803a2a741203c55033c9f7e1b442cd218bd659b440cd21 }


condition:
	$a0
}