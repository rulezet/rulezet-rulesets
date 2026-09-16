rule Win_Trojan_Agent_33060
{
strings:
	$a0 = { 78f5942e577d5154579a0bba3b8b9a0c083d06ffff6f8f08f3ab0d7d952d1808a850ed1c6cbf2d7039550cd1ffffff18c70f24901d1dcc4615cc2a0820c134dd3f5f83f906762d2affd2 }


condition:
	$a0
}