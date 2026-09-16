rule Win_Trojan_Rape_17
{
strings:
	$a0 = { ee03b81042cd213d10427403e9e901b90300bf000181c66f02fcf3a4bf0001ffe73d10427503e97c013d004b7413 }


condition:
	$a0
}