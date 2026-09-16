rule Win_Trojan_Minzhou_1
{
strings:
	$a0 = { 06568b04a300018a4402a20201b802eecd213dfd11745e8cc0488ec026803e00005a754d26a103002d50007244 }


condition:
	$a0
}