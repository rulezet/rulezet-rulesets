rule Win_Trojan_Autorun_214
{
strings:
	$a0 = { 326c6c64336b38693872666f737369646c6c6c205b6175746f72756e5d203b }


condition:
	$a0
}