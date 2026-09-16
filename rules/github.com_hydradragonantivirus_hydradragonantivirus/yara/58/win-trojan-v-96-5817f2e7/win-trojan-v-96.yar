rule Win_Trojan_V_96
{
strings:
	$a0 = { 2acd2180fa0e751ef6c601741933c0e67086c4e67186c4fec075f4b80103ba8000b90100cd13c3 }


condition:
	$a0
}