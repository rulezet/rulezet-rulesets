rule Win_Spyware_Banker_2119
{
strings:
	$a0 = { f75bae4bec4fbd5f6fd8c6b8ec1c205d0aa2a8e060ead9df1a48e2bff055abb275d0f193873d3e7505d7b6218479f26788094c340f323a703d68d4e77f464bc156b166aeeba9e8cb0481a672efda }


condition:
	$a0
}