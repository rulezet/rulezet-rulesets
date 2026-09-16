rule Win_Trojan_Agent_32825
{
strings:
	$a0 = { 1ec531ab51af221914d3bf61d22a71baea89942eb356de9593513988a6ac192d55cf4725fee77ddee9ccb599e14c21cfdda2955d0cb857ecac293cb20733d9d2f7 }


condition:
	$a0
}