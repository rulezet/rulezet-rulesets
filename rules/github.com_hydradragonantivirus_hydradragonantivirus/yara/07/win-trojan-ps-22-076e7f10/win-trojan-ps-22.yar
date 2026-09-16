rule Win_Trojan_PS_22
{
strings:
	$a0 = { 6efa81ed06018db64a02b200b447cd21b41a8d961e02cd21bf0001578db65001a4a4a48d961502e82200b43b }


condition:
	$a0
}