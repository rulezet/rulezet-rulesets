rule Win_Trojan_Macaroni_1
{
strings:
	$a0 = { e800005db84effcd213d494f74181e06b42ccd2180c5042e882e7501e89500061fe8d900071f2e81be4c044d5a74258d }


condition:
	$a0
}