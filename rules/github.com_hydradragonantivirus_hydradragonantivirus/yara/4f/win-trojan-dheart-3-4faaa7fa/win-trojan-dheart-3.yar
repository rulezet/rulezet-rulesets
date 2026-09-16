rule Win_Trojan_DHeart_3
{
strings:
	$a0 = { 1003882611032bc98b160b038b1e0d03b80042cd21722fccba1001b97f028b1e0d03b440cd21cc }


condition:
	$a0
}