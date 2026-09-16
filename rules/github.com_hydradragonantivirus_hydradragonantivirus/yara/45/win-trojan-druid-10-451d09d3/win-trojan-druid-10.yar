rule Win_Trojan_Druid_10
{
strings:
	$a0 = { 57cd215251b440b9390190ba9e00cd21595ab80157cd21b43ecd2159b80143ba9e00cd21b44f }


condition:
	$a0
}