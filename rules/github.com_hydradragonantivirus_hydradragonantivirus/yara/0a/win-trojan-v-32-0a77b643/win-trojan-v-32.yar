rule Win_Trojan_V_32
{
strings:
	$a0 = { 80ea418d1e430acd137222b80103b90110b6008a16b20180e2df80ea418d1e430acd137308 }


condition:
	$a0
}