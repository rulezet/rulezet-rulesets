rule Win_Trojan_XAM_1
{
strings:
	$a0 = { 4a06b452cd212e895d042e8c450607fa8ed9b89702870658003d97027413ab8cc087065a00 }


condition:
	$a0
}