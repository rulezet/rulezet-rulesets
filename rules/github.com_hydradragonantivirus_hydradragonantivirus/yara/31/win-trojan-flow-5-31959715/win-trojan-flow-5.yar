rule Win_Trojan_Flow_5
{
strings:
	$a0 = { e80400909090905db906012be93e80bece020074113e8a86cf028d9e2901b9a501300743e2fb }


condition:
	$a0
}