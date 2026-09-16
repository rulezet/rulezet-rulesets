rule Win_Trojan_Palma5_1
{
strings:
	$a0 = { 50fcf2a4cbff0e13041e061f07ff06fc018b0ef3018b16f1015b53b80102cd13060e07b801 }


condition:
	$a0
}