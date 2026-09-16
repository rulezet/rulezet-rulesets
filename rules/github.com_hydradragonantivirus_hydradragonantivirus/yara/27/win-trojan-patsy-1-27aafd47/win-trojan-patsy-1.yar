rule Win_Trojan_Patsy_1
{
strings:
	$a0 = { 1fb9d902bef8043114310c46e2f93c75912c90901b219297762e2c3116bf41acbfd3c3f482ef8484395ad4f9703f }


condition:
	$a0
}