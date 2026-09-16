rule Win_Trojan_F_27
{
strings:
	$a0 = { e80400909090905db906012be93e80be8b020074113e8a868c028d9e2901b96201300743e2fb }


condition:
	$a0
}