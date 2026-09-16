rule Win_Spyware_WOW_22
{
strings:
	$a0 = { 20fcca87de1fc5e52dbe3726119768b2e45fcd50aa2af1dd84c557cf856d91293d97d351bae2a172c99b0127c2ac14d373f244234397950b16ad3528a42fbead7bc91786 }


condition:
	$a0
}