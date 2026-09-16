rule Win_Trojan_Armageddon_3
{
strings:
	$a0 = { 0e179c58f6c4017403eb33905ee800005eb9f901908d5c2e90b4002e8a0732c42e8807e80e00 }


condition:
	$a0
}