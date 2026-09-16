rule Win_Downloader_285_1
{
strings:
	$a0 = { d21f8e746365d8c38ffac1950210c4e12a008f3c0a170ed02900da32bcdd7d54116e2ae8c54418139ce9e0a7afd28121f25c7a3b3f42f8bf9feec51d483ca1b18f996c09abcd0c6e65e2aba66ac6 }


condition:
	$a0
}