rule Win_Trojan_Hupigon_699
{
strings:
	$a0 = { a2ae00e2cae2a7d3433e902b5d4c371daa9d6d145ea6599d10547545a83840013e079f1a258b161c0357f5d223e3e23eeaf4e4afbb2c4cb94f112fbf }


condition:
	$a0
}