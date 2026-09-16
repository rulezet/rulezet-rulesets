rule Win_Trojan_IpcScan_1
{
strings:
	$a0 = { 2852cbcee2b80a9c8c38a329fab54020c52c525b610386fdaf37157910f964226adfd9524d819fc6713fb8d242e641c2179b933d25b06e737c2981e0f1b7fd90 }


condition:
	$a0
}