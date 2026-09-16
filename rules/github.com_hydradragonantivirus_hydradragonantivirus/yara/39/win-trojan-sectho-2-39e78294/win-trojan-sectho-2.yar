rule Win_Trojan_Sectho_2
{
strings:
	$a0 = { 78657374630f74cbdedd0b25735c0e1e0077dbedffbf2e326e642d74686f756768742e636f6d47696e27612f }


condition:
	$a0
}