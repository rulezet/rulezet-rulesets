rule Win_Trojan_Spooky_1
{
strings:
	$a0 = { 40ba00fdcd2133c933d2b80042cd21595ab440cd2158a31102b801578b1698008b0e9600cd21eb }


condition:
	$a0
}