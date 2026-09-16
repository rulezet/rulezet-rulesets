rule Win_Dropper_Agent_35254
{
strings:
	$a0 = { fffd3a0450ec87fd89289ab23cf0403d4c143a1c62bf78f3c93fbc5057f645d47837a61fc0c6e87a33bfb456bbc8106cad679560ceba3e3209fec196693b448b5b4ca878999e6ebafec4b7d2fe52256d }


condition:
	$a0
}