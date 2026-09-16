rule Win_Trojan_ACV_1
{
strings:
	$a0 = { 803e0401bb7416b91a05908d3e24012e8b3602012e313d2e313547e2f7 }


condition:
	$a0
}