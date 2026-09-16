rule Win_Trojan_Trance_5
{
strings:
	$a0 = { 0290ba0b0103d5cd807211b80156b9baba53bbe10203dd8b175bcd80b43ecd21e82700e927ff }


condition:
	$a0
}