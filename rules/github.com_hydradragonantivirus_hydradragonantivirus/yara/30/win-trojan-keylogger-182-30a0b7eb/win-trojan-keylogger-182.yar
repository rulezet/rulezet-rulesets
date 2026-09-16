rule Win_Trojan_Keylogger_182
{
strings:
	$a0 = { 558bec6aff6860d644 }

	$a1 = { 3132334b65796c6f67676572[0-52]5c696e7669732e737973 }


condition:
	$a0 and $a1
}