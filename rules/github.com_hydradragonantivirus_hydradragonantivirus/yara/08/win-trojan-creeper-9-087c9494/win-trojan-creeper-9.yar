rule Win_Trojan_Creeper_9
{
strings:
	$a0 = { 43cd218cd82d11008ed8803e00015a754fa103012d40 }


condition:
	$a0
}