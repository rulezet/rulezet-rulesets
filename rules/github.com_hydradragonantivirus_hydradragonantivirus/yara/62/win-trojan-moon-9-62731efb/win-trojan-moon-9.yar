rule Win_Trojan_Moon_9
{
strings:
	$a0 = { 6966206e6f7420[0-4]2e68617362796e616d6528[0-15]2e696e7365727462796e616d65 }


condition:
	$a0
}