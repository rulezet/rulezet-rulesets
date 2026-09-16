rule Win_Trojan_Bifrose_149
{
strings:
	$a0 = { 5ae765dcdcf49ff1ac9a4d4b944c99c1ea4bf27fbb8f8111e217e446a90d5ec497c452c3637575f4ab997ab27ebf5ba0a3310b89de0c4d74330c26c5f05835b47f602f3914fdabbb5a3e597d764cb87f }


condition:
	$a0
}