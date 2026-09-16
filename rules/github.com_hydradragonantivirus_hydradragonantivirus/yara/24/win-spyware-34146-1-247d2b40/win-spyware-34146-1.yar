rule Win_Spyware_34146_1
{
strings:
	$a0 = { b8d8764000e8cce4ffff8bd08bc38b0dd4764000e839d5ffffb891000000e89ffdffff8d4de8ba6c544000a1d8764000e8cdeaffff }


condition:
	$a0
}