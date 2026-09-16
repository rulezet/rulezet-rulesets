rule Win_Trojan_Expiro_13
{
strings:
	$a0 = { 60e828af01009061e9??????ff??c5 }


condition:
	$a0
}