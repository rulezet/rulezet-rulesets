rule Win_Trojan_Happy_2
{
strings:
	$a0 = { 01568dbc190181c61201b9070090fcf3a45e8bec83ec2cb41a8bd48bfa50cd21 }


condition:
	$a0
}