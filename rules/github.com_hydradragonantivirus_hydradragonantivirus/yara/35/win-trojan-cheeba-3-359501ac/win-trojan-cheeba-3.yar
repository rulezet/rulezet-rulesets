rule Win_Trojan_Cheeba_3
{
strings:
	$a0 = { be0001fc2e8034714681fe680775f5 }


condition:
	$a0
}