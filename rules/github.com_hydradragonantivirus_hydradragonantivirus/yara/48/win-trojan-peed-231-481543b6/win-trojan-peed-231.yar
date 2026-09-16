rule Win_Trojan_Peed_231
{
strings:
	$a0 = { b85468220087fb73386846630300ff1533774300ff1648525589e551418b7d0c }


condition:
	$a0
}