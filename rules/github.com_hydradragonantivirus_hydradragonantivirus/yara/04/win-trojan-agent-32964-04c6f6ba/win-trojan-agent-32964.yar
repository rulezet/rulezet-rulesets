rule Win_Trojan_Agent_32964
{
strings:
	$a0 = { 24d99a8bd4d6ad488b26d42a4b84e6a90dbd1be2d02f861048e4c6904d4e4e5e9ea214c8caa3962844fb4c050c2e0e4fffabd2f54470f5622853a7ae4bca0b6ba9a6aecbdef0c7eb3b3d5ede3721 }


condition:
	$a0
}