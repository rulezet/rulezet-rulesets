rule Win_Trojan_Hardcore_1
{
strings:
	$a0 = { 33db8a87e90688873e083c0074064383fb0d75ee33db2e8a0788874b084381fb000175f2b44eb90f00ba }


condition:
	$a0
}