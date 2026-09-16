rule Win_Trojan_Mybot_7248
{
strings:
	$a0 = { 88ba0e1c17ffa2b9d3a32482262fea5e76a99c6b26eaed5d223944edbd9012ca914c8100cde98a6e5fadec522acf143e9a14f04875a89b039fea1e61f7d8541aed5437c224e40fcb41be74d07fbd }


condition:
	$a0
}