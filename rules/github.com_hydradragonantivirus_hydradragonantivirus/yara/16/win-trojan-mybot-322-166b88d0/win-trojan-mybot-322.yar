rule Win_Trojan_Mybot_322
{
strings:
	$a0 = { 304e5c6763843abecf3232484cc752ff24fddd3d5dfecefaef3214b0c13a3246494641e5deabff0a3a05acd4f1f72f3232cc63b0866f672d327f693a20ae }


condition:
	$a0
}