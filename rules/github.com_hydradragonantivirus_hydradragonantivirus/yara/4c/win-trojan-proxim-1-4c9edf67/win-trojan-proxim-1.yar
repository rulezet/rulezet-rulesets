rule Win_Trojan_Proxim_1
{
strings:
	$a0 = { 60e8319801009061e9f3????????c3 }

	$a1 = { c4185f5ec9c35589e583ec2053565766c745fe0000c745f005000000c745f406000000c745ec030000008d3dc6 }


condition:
	$a0 and $a1
}