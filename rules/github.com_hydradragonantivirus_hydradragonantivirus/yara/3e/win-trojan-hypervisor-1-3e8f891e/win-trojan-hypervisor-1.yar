rule Win_Trojan_Hypervisor_1
{
strings:
	$a0 = { fefb061f2effae9cfe33c08ed8832e1304049058 }


condition:
	$a0
}