rule Win_Trojan_RiotCoke_1
{
strings:
	$a0 = { b801faba4559cd161e0e070e1fe800005d81ed10018dbee2018db6ea01e80b00e80800e80500e80200eb02a5c38d963103b41acd21b447b2008db65d03cd21b4 }


condition:
	$a0
}