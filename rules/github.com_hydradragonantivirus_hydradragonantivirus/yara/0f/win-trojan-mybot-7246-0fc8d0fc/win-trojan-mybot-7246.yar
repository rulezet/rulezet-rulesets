rule Win_Trojan_Mybot_7246
{
strings:
	$a0 = { 463e8074c7d9fd6c9436e8da19e95f660ffbeadbbadb3139ea6f8db5e5ccf06b2c41517306fd81cf69cd3cf4db03748803edd44d14da4c44a3e12a60bc9c5337ddd906368cf3ea98646bdb7c3282 }


condition:
	$a0
}