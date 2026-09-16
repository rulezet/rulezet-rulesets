rule Win_Trojan_Enough_3
{
strings:
	$a0 = { 2e8135530547474d75f6bb05535d7e16538ebb1b55bd1d449e246e4c07713b86b005e74f18c87286b85fe74f9e242152d02b }


condition:
	$a0
}