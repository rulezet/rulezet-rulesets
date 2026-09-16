rule Win_Trojan_Bancos_976
{
strings:
	$a0 = { a8ac44acc331bf04281e0d373edcf931420f3c5c95094e7c34ca237b5b74b45331f3ae040651befaa9439ba2981c0ecb4b76e0b4ca77cb52421a6dfc73d7cf116e0b7e3b5ddd0be20ef943c4f38118adccc2 }


condition:
	$a0
}