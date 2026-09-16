rule anti_debug__PeID_GenOEP_Spoofing__8_byt_48_
{
strings:
	$a0 = { 558bec6aff68f840400068f41d400064a100000000506489250000000083ec585356578965e8ff155840400033d28ad4 }

condition:
	$a0
}