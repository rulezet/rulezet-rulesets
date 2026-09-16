rule Win_Spyware_WOW_18
{
strings:
	$a0 = { 056e0b2a0bccd5dc91d8913a08b8f352cfae424f261bb0cb78828578b97b0adf8f8ad335905be2c05d31af9c469a14d8488b39b9dba1da31d5c73badc6a431d5a73f25d7 }


condition:
	$a0
}