rule Win_Trojan_EVC_6
{
strings:
	$a0 = { bbfe01c00fdf4381fb9a057cf6740000aec1f6817474015cc74196791e9a4c83e6909e1a09ba0cc65bc881dfb9b3c0e32152c0fbda }


condition:
	$a0
}