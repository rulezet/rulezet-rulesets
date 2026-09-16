rule Win_Trojan_Hupigon_694
{
strings:
	$a0 = { a125d1db6b494c79dc1dcd2cb4ec305335dd0aa9a872e47aa40a71fd8b9cc3e8a3fd45ae2076679e038e8fba05ccf3a3734e15f9dddcf00ee3cff74f59074d633c }


condition:
	$a0
}