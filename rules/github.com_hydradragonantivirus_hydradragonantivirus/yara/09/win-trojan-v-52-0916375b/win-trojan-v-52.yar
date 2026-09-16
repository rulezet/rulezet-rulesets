rule Win_Trojan_V_52
{
strings:
	$a0 = { 5152535556571e0e1fe80900eb18e804008bcdcd21b9eb00be2800fc9c8134 }


condition:
	$a0
}