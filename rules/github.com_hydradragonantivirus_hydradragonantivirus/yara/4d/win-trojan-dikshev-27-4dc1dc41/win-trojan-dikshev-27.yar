rule Win_Trojan_Dikshev_27
{
strings:
	$a0 = { 01cd21721e568bf2acacbf9c00a58bd7f2ae91f3a4b45bcd215a720793b131b440cd21c32a2e }


condition:
	$a0
}