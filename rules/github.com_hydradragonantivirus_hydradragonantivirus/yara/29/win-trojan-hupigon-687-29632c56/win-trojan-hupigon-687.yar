rule Win_Trojan_Hupigon_687
{
strings:
	$a0 = { 000363d420d84b6f1312782d96a1ab2fc28f3e75117e63d7e54f7ef6fdb7e5bac32547d85d6b8e89223b18e87e8797e77908fbf7a2483bcf45a78d49 }


condition:
	$a0
}