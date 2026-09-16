rule Win_Trojan_Pepe_2
{
strings:
	$a0 = { 56525153500efc8cc82e01064900ba9e0103c28bd8052c018edb8ec033f633ffb90800f3a54b }


condition:
	$a0
}