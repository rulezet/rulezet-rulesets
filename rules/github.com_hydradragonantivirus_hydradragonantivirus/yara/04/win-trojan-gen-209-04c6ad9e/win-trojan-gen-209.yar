rule Win_Trojan_Gen_209
{
strings:
	$a0 = { 71f1fd7808f0f26c351e06bafb52ba80ffd0fb9a5400900583c4084547071fa9e809b72ef0 }


condition:
	$a0
}