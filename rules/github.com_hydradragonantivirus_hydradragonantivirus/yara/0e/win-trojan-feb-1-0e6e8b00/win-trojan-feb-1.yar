rule Win_Trojan_Feb_1
{
strings:
	$a0 = { b914028cc283ea03cd21b8024233c933d2cd21b440b1038cc281c21402cd21b801438a4e03ba }


condition:
	$a0
}