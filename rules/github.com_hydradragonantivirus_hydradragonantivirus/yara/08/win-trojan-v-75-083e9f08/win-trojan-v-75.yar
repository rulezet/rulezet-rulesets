rule Win_Trojan_V_75
{
strings:
	$a0 = { 0358b109d3e801066c038b1e8103b000e8a800a07903fec8a27a03b440b91800ba6803cd21eb }


condition:
	$a0
}