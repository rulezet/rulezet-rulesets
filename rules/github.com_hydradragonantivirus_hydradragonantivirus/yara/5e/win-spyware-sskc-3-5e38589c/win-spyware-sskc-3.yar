rule Win_Spyware_SSKC_3
{
strings:
	$a0 = { 4b433e7a185bcd458d2868d69be45b70bb37768c83e643817a42f64b5455078cef2feda52355137636e890f30e932098c301 }


condition:
	$a0
}