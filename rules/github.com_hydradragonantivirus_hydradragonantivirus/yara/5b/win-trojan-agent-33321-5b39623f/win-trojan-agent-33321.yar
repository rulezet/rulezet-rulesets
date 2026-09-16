rule Win_Trojan_Agent_33321
{
strings:
	$a0 = { accfaa55f4712ab19e2bfcb2b98ba3f4924e9d453a5fe6f92d25fa4bec195f784636d2dacfc50563df9cfc893faff94baecf348944afe4a7faa53127d4f13810ab20f97ca15a0c1791b97d74fb13 }


condition:
	$a0
}