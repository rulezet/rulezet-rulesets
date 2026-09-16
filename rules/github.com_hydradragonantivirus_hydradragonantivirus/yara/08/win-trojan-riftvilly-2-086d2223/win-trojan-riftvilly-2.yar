rule Win_Trojan_RiftVilly_2
{
strings:
	$a0 = { 018b2e01018db67801f71457b90300f3a4b4f1cd2181fba40874578cc8488ec026832e03001f }


condition:
	$a0
}