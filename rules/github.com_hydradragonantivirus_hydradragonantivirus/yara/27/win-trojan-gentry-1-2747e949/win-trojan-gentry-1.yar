rule Win_Trojan_Gentry_1
{
strings:
	$a0 = { 0443ff0fcd12b106d3e08ec033ffbe007cb90001fcf3a5bb47000653cb5233d2b400cd1ab8f0 }


condition:
	$a0
}