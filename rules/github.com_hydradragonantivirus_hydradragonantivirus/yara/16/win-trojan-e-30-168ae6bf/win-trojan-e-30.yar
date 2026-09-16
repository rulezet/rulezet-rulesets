rule Win_Trojan_E_30
{
strings:
	$a0 = { cd21b8024abb7401cd2f477504b001eb664f893efd0157be0001b97401f3a45fb870008ed8beb40081c7f200a5a5 }


condition:
	$a0
}