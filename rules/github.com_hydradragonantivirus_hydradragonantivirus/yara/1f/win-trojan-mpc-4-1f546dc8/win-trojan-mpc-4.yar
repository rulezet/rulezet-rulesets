rule Win_Trojan_MPC_4
{
strings:
	$a0 = { cc8b6efa81ed13001e06b84144cd213d53507458b44abbffffcd2183eb4690b44acd21724783 }


condition:
	$a0
}