rule Win_Trojan_Peak_1
{
strings:
	$a0 = { 160500cdd3b801028b0e03008b160500bb007ccdd3cb2e88262a012e88162b01cdd3721c9c2e80 }


condition:
	$a0
}