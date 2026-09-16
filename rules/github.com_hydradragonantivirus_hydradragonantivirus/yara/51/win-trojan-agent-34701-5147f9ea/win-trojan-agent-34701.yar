rule Win_Trojan_Agent_34701
{
strings:
	$a0 = { eb198500b9d2ea009f00ca000023000a95006f7100fc00b100df0001c829c981c1a4ff1200f7df545a }


condition:
	$a0
}