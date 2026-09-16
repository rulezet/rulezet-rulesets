rule Win_Trojan_Agent_35181
{
strings:
	$a0 = { 9ce8000000005f85c58bdf46fcfd81ef301001008bd1fc0fbef157480fbdc681c3390000004056586800000000 }


condition:
	$a0
}