rule Win_Trojan_Micro_2
{
strings:
	$a0 = { 4b753b5053521eb8023dcde072288bd80e1fe8d7ffb4 }


condition:
	$a0
}