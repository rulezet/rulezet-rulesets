rule Win_Trojan_Runme_3
{
strings:
	$a0 = { 9a00003b005589e531c09acd023b00e8f9fce81bfde820ff803e1a2700750ce8e1fde80dfee857ffe872fd5d31c09a16 }


condition:
	$a0
}