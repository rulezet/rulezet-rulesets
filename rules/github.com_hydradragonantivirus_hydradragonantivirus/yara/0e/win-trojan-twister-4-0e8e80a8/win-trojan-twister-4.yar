rule Win_Trojan_Twister_4
{
strings:
	$a0 = { 4ceb0188b4ff90cd21eb019afecc3d01007441b430be1044cd213c037236e843008cdefdacfc8ec633f626803c5a }


condition:
	$a0
}