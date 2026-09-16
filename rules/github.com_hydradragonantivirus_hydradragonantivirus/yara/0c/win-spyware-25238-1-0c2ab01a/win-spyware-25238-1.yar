rule Win_Spyware_25238_1
{
strings:
	$a0 = { 2bc6f96083e04d8bc6e80b000000fc33c2e907000000f973080bc7c39823c2f5 }


condition:
	$a0
}