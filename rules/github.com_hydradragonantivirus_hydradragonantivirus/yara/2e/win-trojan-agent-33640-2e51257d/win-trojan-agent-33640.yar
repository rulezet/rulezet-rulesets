rule Win_Trojan_Agent_33640
{
strings:
	$a0 = { 60a0eaf5a8415bddb820cc7caea3e241a70e360d3a02f4635c4fda03d793170d2c9ac01a63653a73236cd223bdf4bc5f5d38af066fe13468b66c82d295fa4c2cdd726efbcfa91efb05e23556ff0573f61d84 }


condition:
	$a0
}