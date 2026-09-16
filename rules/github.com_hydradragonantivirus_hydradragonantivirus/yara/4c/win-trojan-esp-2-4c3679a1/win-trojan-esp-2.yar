rule Win_Trojan_ESP_2
{
strings:
	$a0 = { b90300bab105b440cd21b8024233d233c9cd21b4405a52b90a212bca81c20001cd21b80057 }


condition:
	$a0
}