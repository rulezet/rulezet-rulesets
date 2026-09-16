rule Win_Trojan_Monika_2
{
strings:
	$a0 = { ee111e0e1f8c9c82008b04a300018a4402a202018b84b100a32908b828dccd213d731974448cc8488ec026803e00 }


condition:
	$a0
}