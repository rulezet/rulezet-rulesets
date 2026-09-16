rule Win_Trojan_SillyC_8
{
strings:
	$a0 = { b440b94d03ba06012bca8d960601cd217249e85600b801578b8ede018b96e001cd21b43e8b }


condition:
	$a0
}