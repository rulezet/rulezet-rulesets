rule Win_Trojan_Sirius_5
{
strings:
	$a0 = { 28ece504bb850a1ae9bc17fa27256afa781d9943ddc461dc351a7504dc8d6da7f52a799a53057bcf }


condition:
	$a0
}