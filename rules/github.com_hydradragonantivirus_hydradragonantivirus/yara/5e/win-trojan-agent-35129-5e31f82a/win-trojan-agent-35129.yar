rule Win_Trojan_Agent_35129
{
strings:
	$a0 = { a15d7cd9b6a90b5ed800da15f53aebed73114ccd53a7d296d868b347c773518e73f34f4bd278c23accf33de4d74f4b81b2dc5705b57d6fd587f8e3054cdca01af7e0050374e3b816cce030eb2fb55b65 }


condition:
	$a0
}