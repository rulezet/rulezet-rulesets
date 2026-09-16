rule Win_Trojan_Bolek_1
{
strings:
	$a0 = { 03b869008cda03c20510005053061ee84203e89a01e85301e89301e84e0333db33c933d233f633ff1f07cbb80043 }


condition:
	$a0
}