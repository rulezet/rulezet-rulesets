rule Win_Trojan_Pieck_1
{
strings:
	$a0 = { eb0e00fe000000000000000000000000be0c00fa2e89a40b082e8c940d088cc88ed0bc6018fb561e06b8ffffbb7203cd213d72 }


condition:
	$a0
}