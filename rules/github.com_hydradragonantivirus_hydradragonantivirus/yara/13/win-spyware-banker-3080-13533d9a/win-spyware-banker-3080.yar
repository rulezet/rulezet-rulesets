rule Win_Spyware_Banker_3080
{
strings:
	$a0 = { 6dc14cdba91ad74049547478ee0fa9ce9f8df736145accdeb7f0aec399e03f83a63015379c1efcbd8f59682ecad286723a6e1692e1c9d90978b761b03be4 }


condition:
	$a0
}