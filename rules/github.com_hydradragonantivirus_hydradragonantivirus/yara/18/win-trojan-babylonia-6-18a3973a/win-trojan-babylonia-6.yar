rule Win_Trojan_Babylonia_6
{
strings:
	$a0 = { 20000051538b5d0c80fb21740880fb24740380fb2590e9250600008bdd60e87206000066c7451b }


condition:
	$a0
}