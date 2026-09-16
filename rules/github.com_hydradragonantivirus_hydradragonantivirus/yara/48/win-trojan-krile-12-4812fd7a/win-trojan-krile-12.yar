rule Win_Trojan_Krile_12
{
strings:
	$a0 = { 4aeaa1209f109d1c9b1a991897169514931291108f0e8d0c8b0a890887068504830281167fac72fc7bfa79f877 }


condition:
	$a0
}