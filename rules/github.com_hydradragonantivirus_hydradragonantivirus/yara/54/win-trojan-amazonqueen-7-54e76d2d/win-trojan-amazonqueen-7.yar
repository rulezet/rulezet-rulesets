rule Win_Trojan_AmazonQueen_7
{
strings:
	$a0 = { 81ed0500444406ff86f201b4accd213c3075132e3b9ef001 }


condition:
	$a0
}