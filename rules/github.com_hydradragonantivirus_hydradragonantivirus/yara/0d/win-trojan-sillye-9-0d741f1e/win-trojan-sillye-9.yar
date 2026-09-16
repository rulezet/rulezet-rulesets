rule Win_Trojan_SillyE_9
{
strings:
	$a0 = { 405a59cd21e83600b440b93302ba0001cd21b801578b36ec028b54188b4c16cd21b43ecd21b801 }


condition:
	$a0
}