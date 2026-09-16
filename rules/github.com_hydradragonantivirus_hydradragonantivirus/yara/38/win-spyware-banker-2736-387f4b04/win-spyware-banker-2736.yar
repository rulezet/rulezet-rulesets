rule Win_Spyware_Banker_2736
{
strings:
	$a0 = { cbe2587139badec2d6c5ce076d9a2893730b5068381add6a081fd3e6fa55055dd510413b92ae44c57ddc1bef0ea5a7ce7c07aee9f5f24c098baa3dc79c9dfd79e654b5590e3511e8c0f4c44e9cad }


condition:
	$a0
}