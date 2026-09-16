rule Win_Trojan_VGEN_583
{
strings:
	$a0 = { 09ba6401cd21b82c09b104d3e88ccb03d88ec3b9320051b43c33c9ba5701cd2193bd0001b91f00ba8e0153e8970693 }


condition:
	$a0
}