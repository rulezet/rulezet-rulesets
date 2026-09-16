rule Win_Trojan_HarmWare_2
{
strings:
	$a0 = { 185d50d594801c29570edf11c2155df8cf15685f1137641784d5fd49641884d6fd4c57e9671fdca7 }


condition:
	$a0
}