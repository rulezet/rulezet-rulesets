rule Win_Trojan_Uyuz_1
{
strings:
	$a0 = { 8c06480a2e8c1e4a0a2ec606c705000e0e1f07b8b1a9cd213de5c374562ec606c70501fa1e33c08ed8c41e84001f89 }


condition:
	$a0
}