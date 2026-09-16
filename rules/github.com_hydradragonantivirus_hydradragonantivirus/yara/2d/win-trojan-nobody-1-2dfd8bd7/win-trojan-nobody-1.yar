rule Win_Trojan_Nobody_1
{
strings:
	$a0 = { 6a02b43f8d962302b90300cd2172378b865a028b8e240281c13e013bc174272d030089863e02 }


condition:
	$a0
}