rule Win_Dropper_Agent_35801
{
strings:
	$a0 = { b94c19655e558bec83ec3081e9b135ed00428bc12bca81ea9108c644c981c94e }


condition:
	$a0
}