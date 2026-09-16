rule Win_Trojan_Jester_2_1
{
strings:
	$a0 = { 1e0656570e1f2e8b360101b430cd213c027706e9e200e9ae00e82701e88601e8e400e80801b44eb92300ba1503 }


condition:
	$a0
}