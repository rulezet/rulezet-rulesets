rule Win_Trojan_Duwende_6
{
strings:
	$a0 = { ba511cf0a81d9c20f5b34a9d6d672081ae216496a62feba6a6bf3408c235b40c0a733c00d83f33ba080fa1e6c1669fb8 }


condition:
	$a0
}