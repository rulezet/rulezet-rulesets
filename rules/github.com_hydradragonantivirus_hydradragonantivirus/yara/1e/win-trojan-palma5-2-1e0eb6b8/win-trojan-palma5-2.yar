rule Win_Trojan_Palma5_2
{
strings:
	$a0 = { 50fcf2a4cb8ed8ebebff8d13021e061f07fe06fd018b0ef3018b16f1015b53b8010250cd13 }


condition:
	$a0
}