rule Win_Trojan_Kiss_2
{
strings:
	$a0 = { 743a80fc12743580fc1a742380fc3d74dd80fc4b74d880fc }


condition:
	$a0
}