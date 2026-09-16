rule Win_Trojan_Monster_16
{
strings:
	$a0 = { bedc2c8034cd46e2fa26e996ed8082839e99889fed9091cde7e3e7cde7e38e8280cd14bbd92400e6cdfdd859dd }


condition:
	$a0
}