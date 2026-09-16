rule Win_Trojan_Chemist_5
{
strings:
	$a0 = { be10018a2480f4aa882446e2f61e06678b973bb3dfa9432eaa266287abaa247211a9aa21ad872aaa23ada4b511a8aa21ad872aaa23ad246a15aaaa14aa }


condition:
	$a0
}