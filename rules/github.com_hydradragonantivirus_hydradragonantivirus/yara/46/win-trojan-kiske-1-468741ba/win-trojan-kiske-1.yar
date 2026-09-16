rule Win_Trojan_Kiske_1
{
strings:
	$a0 = { 81ed0701bf00018db61404fca5a5cc1e06b80535cd218bd38cc08ed8b83325cd21b80335cd218cc08ed8c607cf071f }


condition:
	$a0
}