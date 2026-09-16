rule Win_Spyware_Banker_2365
{
strings:
	$a0 = { 0331ec2f3f1ee345e359221c2fbe24056ece2f60eb648e9107c2f65b1e099de96068fde30b972c79c1eb317c34a2f259a842c9a72d0ba39ab9bd7f3b8647f8e3bf5c8ec2bed8f8f1321b }


condition:
	$a0
}