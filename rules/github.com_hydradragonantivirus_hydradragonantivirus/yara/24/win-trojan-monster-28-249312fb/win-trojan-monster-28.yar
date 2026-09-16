rule Win_Trojan_Monster_28
{
strings:
	$a0 = { 02bede2c8034cd46e2faeb2696ed8082839e99889fed9091cde7e3e7cde7e38e8280cd0ba4ec2400e6cde2edcdcd }


condition:
	$a0
}