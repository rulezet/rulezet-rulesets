rule Win_Trojan_Mozilla_2
{
strings:
	$a0 = { 3c6120687265663d68747470733aadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad3e }


condition:
	$a0
}