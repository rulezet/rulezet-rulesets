rule Win_Trojan_S_1
{
strings:
	$a0 = { fb5943fcc545b6e1fd47bff674ff001c885343fd6170ccdb1b46c9c32546886442fd6160 }


condition:
	$a0
}