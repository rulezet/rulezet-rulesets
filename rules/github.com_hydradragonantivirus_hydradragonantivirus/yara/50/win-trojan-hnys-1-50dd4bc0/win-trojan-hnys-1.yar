rule Win_Trojan_HNYS_1
{
strings:
	$a0 = { 8512885032e8315aadad2f7a31202e69f9272aea3110029b0280adad2f7a31203ce671eb32528be2 }


condition:
	$a0
}