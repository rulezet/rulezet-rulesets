rule Win_Trojan_Proxy_70
{
strings:
	$a0 = { 81db5e5d21175b575333dbeb028a185b7e00bf4a9100785f81d9a20c5d158b151841410033cf8bdb2bfa03c3bb1399808b0f }


condition:
	$a0
}