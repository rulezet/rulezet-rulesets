rule Win_Trojan_Creeper_8
{
strings:
	$a0 = { 90cd218cd82d11008ed8803e00015a754fa103012d }


condition:
	$a0
}