rule Win_Trojan_Loki_6
{
strings:
	$a0 = { 89de81c6a603b90500f3a4cd713d9999750bb8000133f633f733c9ffe089df81ef000133c08ec026a18400268b }


condition:
	$a0
}