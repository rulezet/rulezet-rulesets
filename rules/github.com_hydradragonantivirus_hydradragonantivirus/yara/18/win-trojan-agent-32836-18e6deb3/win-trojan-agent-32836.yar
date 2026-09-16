rule Win_Trojan_Agent_32836
{
strings:
	$a0 = { 9a6e83644336e9ba0a5167ce82303e5dc7cacc86f8821388ae74b8dcc13e883d42f8ff8d55e0159a6fd9e56b0853317f18e4ca087830b0e02ca6f423a9865a6eb7 }


condition:
	$a0
}