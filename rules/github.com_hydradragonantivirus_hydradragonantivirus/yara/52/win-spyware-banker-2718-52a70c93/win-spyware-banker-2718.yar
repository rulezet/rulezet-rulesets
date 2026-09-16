rule Win_Spyware_Banker_2718
{
strings:
	$a0 = { 5c97755c4048a6bf093b5fe5ac5aaa352117a2b72969ada952888b461b28f02a4db7cb54b3b83fc8858dd51d27f0c716c0d4fbfd6b1fe4dbd326bc59ed5f472a62a8115f5c9b1aac6f0a80431927 }


condition:
	$a0
}