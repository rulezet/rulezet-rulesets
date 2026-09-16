rule Win_Trojan_Hypervisor_2
{
strings:
	$a0 = { a69afefb061f2effae9cfe33c08ed8812e1304040058 }


condition:
	$a0
}